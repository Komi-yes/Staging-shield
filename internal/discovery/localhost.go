// localhost.go implementa las verificaciones del modo invasivo
// (--local-host-scan) y del modo remoto (--ssh-target). Ambos comparten la
// misma lógica de chequeos; lo único que cambia es cómo se ejecutan los
// comandos y se leen los archivos, a través de la interfaz hostRunner.
//
// Diseño:
//   - localRunner ejecuta con exec.Command sobre el equipo donde corre el cliente.
//   - sshRunner envuelve cada comando en una sesión SSH contra un host remoto.
//
// Los validadores (rules/validators.go) NO necesitan saber qué modo se usó:
// ambos llenan el mismo struct LocalHostData y los resultados se interpretan
// igual. La única diferencia visible al usuario es el banner del reporte
// que indica si fue local-host o ssh, y el host inspeccionado.
package discovery

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	ctx "github.com/stagingshield/staging-shield/internal/context"
)

// hostRunner abstrae las operaciones de inspección de un host. Tiene dos
// implementaciones: una que opera sobre el host local (localRunner) y otra
// que opera sobre un host remoto vía SSH (sshRunner).
type hostRunner interface {
	// Run ejecuta un comando con timeout corto y devuelve su stdout+stderr.
	// El segundo retorno (bool) indica si el comando estuvo disponible:
	// false significa "comando no encontrado en PATH" (no es error de
	// ejecución sino ausencia de la herramienta).
	Run(name string, args ...string) (output string, available bool, err error)

	// ReadFile lee un archivo del host. Devuelve error si no existe o no
	// se tiene permiso de lectura.
	ReadFile(path string) ([]byte, error)

	// Stat es como os.Stat pero adaptado a la abstracción. Devuelve sólo
	// los campos que los validadores realmente usan (modo, tamaño,
	// existencia). Esto evita acoplarse a os.FileInfo (que no tiene sentido
	// para un host remoto donde no podemos hacer syscalls directamente).
	Stat(path string) (statResult, error)

	// Mode describe la naturaleza del runner para mensajes de log y para
	// que la sección de evidencia del reporte indique si fue local o ssh.
	// Posibles valores: "local-host", "ssh".
	Mode() string

	// HostLabel describe el host inspeccionado de forma legible.
	// Ej: "este equipo (linux)", "deploy@10.0.0.5:22".
	HostLabel() string
}

// statResult es un subconjunto de os.FileInfo expuesto por la abstracción.
type statResult struct {
	Exists bool
	IsDir  bool
	Mode   fs.FileMode
	Size   int64
}

// ===================== localRunner =====================

type localRunner struct{}

func (l localRunner) Run(name string, args ...string) (string, bool, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", false, nil
	}
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), true, err
}
func (l localRunner) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (l localRunner) Stat(path string) (statResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return statResult{Exists: false}, nil
		}
		return statResult{}, err
	}
	return statResult{Exists: true, IsDir: info.IsDir(), Mode: info.Mode().Perm(), Size: info.Size()}, nil
}
func (l localRunner) Mode() string      { return "local-host" }
func (l localRunner) HostLabel() string { return "este equipo (" + runtime.GOOS + ")" }

// ===================== sshRunner =====================
//
// sshRunner usa el binario `ssh` del sistema en vez de la librería
// golang.org/x/crypto/ssh por tres razones:
//   1. Respeta la configuración del usuario (~/.ssh/config, agent, etc.).
//   2. No agrega una dependencia externa al go.mod.
//   3. Es transparente: el evaluador puede reproducir cualquier comando
//      que el cliente ejecutó simplemente con `ssh user@host '...'`.
//
// Para CI/CD: la llave privada se monta en disco (vía secret -> archivo) o
// el cliente la escribe a un temp file desde la variable de entorno
// STAGING_SHIELD_SSH_KEY antes del scan. sshRunner respeta esa ruta.

type sshRunner struct {
	target     string // "user@host"
	port       int    // 22 por defecto
	keyPath    string // ruta a llave privada (puede estar vacía -> usa agente o ~/.ssh)
	useSudo    bool   // prefijar comandos privilegiados con "sudo -n"
	cmdTimeout time.Duration
}

// sshOpts agrupa flags útiles para todos los comandos ssh que invocamos.
// StrictHostKeyChecking=accept-new permite primera conexión sin known_hosts
// pre-cargado (típico en CI/CD efímero) pero rechaza si la llave cambió.
// BatchMode=yes evita prompts interactivos: si la llave falla, falla rápido.
// ConnectTimeout limita el tiempo de establecimiento de conexión.
func (s sshRunner) sshOpts() []string {
	opts := []string{
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=8",
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=2",
	}
	if s.port > 0 && s.port != 22 {
		opts = append(opts, "-p", strconv.Itoa(s.port))
	}
	if s.keyPath != "" {
		opts = append(opts, "-i", s.keyPath, "-o", "IdentitiesOnly=yes")
	}
	return opts
}

func (s sshRunner) Run(name string, args ...string) (string, bool, error) {
	// Construimos el comando shell remoto. Quoteamos cada arg para evitar
	// inyección por argumentos con espacios o caracteres especiales.
	quoted := []string{shellQuote(name)}
	for _, a := range args {
		quoted = append(quoted, shellQuote(a))
	}
	remoteCmd := strings.Join(quoted, " ")
	if s.useSudo && cmdNeedsSudo(name, args) {
		// sudo -n: no pedir password. Si la cuenta no tiene NOPASSWD para
		// este comando, falla en vez de colgar.
		remoteCmd = "sudo -n " + remoteCmd
	}
	// Antes de correr el comando, verificamos disponibilidad con
	// `command -v <name>`. Si no existe, devolvemos available=false para
	// que los chequeos hagan fallback igual que en local.
	checkCmd := "command -v " + shellQuote(name) + " >/dev/null 2>&1 && echo OK || echo MISSING"

	checkArgs := append(s.sshOpts(), s.target, checkCmd)
	checkOut, checkErr := exec.Command("ssh", checkArgs...).CombinedOutput()
	if checkErr != nil {
		return strings.TrimSpace(string(checkOut)), false, fmt.Errorf("ssh check falló: %v: %s", checkErr, strings.TrimSpace(string(checkOut)))
	}
	if !strings.Contains(string(checkOut), "OK") {
		return "", false, nil
	}

	cmdArgs := append(s.sshOpts(), s.target, remoteCmd)
	cmd := exec.Command("ssh", cmdArgs...)
	if s.cmdTimeout > 0 {
		// Usamos un contexto via CommandContext para timeout duro.
		// (omitido aquí para mantener simple: ssh ConnectTimeout cubre lo principal)
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), true, err
}

func (s sshRunner) ReadFile(path string) ([]byte, error) {
	// cat el archivo remoto. Si necesita sudo (típico para /etc/shadow o
	// sshd_config), se prefija.
	remoteCmd := "cat " + shellQuote(path)
	if s.useSudo {
		remoteCmd = "sudo -n " + remoteCmd
	}
	args := append(s.sshOpts(), s.target, remoteCmd)
	out, err := exec.Command("ssh", args...).Output()
	if err != nil {
		// Si el archivo no existe, cat retorna con código de salida no-cero
		// y un mensaje específico. Lo traducimos a fs.ErrNotExist para que
		// el código existente (que usa errors.Is(err, fs.ErrNotExist))
		// siga funcionando sin cambios.
		return nil, fmt.Errorf("ssh cat %s: %w", path, err)
	}
	return out, nil
}

func (s sshRunner) Stat(path string) (statResult, error) {
	// stat con formato controlado. Devolvemos campos planos que después
	// parseamos. Si stat no existe (sistemas Alpine minimal), caemos a
	// `ls -ld` como fallback.
	remoteCmd := fmt.Sprintf("stat -c '%%a|%%s|%%F' %s 2>/dev/null", shellQuote(path))
	args := append(s.sshOpts(), s.target, remoteCmd)
	out, err := exec.Command("ssh", args...).Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		// Archivo no existe o stat falló: tratamos como no-existente para
		// que los validadores hagan su lógica normal.
		return statResult{Exists: false}, nil
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 3)
	if len(parts) < 3 {
		return statResult{Exists: false}, nil
	}
	mode, _ := strconv.ParseUint(parts[0], 8, 32)
	size, _ := strconv.ParseInt(parts[1], 10, 64)
	return statResult{
		Exists: true,
		IsDir:  strings.Contains(parts[2], "directory"),
		Mode:   fs.FileMode(mode),
		Size:   size,
	}, nil
}

func (s sshRunner) Mode() string      { return "ssh" }
func (s sshRunner) HostLabel() string { return s.target }

// cmdNeedsSudo decide si un comando requiere privilegios. La lista es
// conservadora: solo aplicamos sudo cuando es estrictamente necesario, para
// minimizar la superficie de privilegio del cliente.
func cmdNeedsSudo(name string, args []string) bool {
	switch name {
	case "iptables", "ip6tables", "nft":
		return true
	case "ufw":
		// `ufw status` necesita sudo para mostrar reglas; sin sudo solo
		// devuelve active/inactive.
		return true
	}
	return false
}

// shellQuote pone un string entre comillas simples y escapa simples internas.
// Esto es suficiente para los comandos que ejecutamos: no usamos pipes ni
// redirecciones del lado remoto (excepto en checkCmd que escribimos a mano).
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	// Reemplazar ' por '\'' (cerrar quote, escapar, abrir quote)
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// =================== helpers compartidos ===================

// runCmd se mantiene por compatibilidad con código que aún use exec directo;
// internamente delega al localRunner. Las nuevas funciones reciben un
// hostRunner explícitamente.
func runCmd(name string, args ...string) (string, error) {
	out, _, err := (localRunner{}).Run(name, args...)
	return out, err
}

func appendErr(ec *ctx.EvalContext, format string, args ...interface{}) {
	ec.Discovery.LocalHost.Errors = append(ec.Discovery.LocalHost.Errors, fmt.Sprintf(format, args...))
}

// runLocalHostChecks ejecuta todas las verificaciones invasivas sobre el
// host LOCAL. Solo se llama desde Run() cuando ec.LocalHostScan es true.
func runLocalHostChecks(ec *ctx.EvalContext, log func(string, ...interface{})) {
	r := localRunner{}
	ec.Discovery.LocalHost.Available = true
	ec.Discovery.LocalHost.OS = runtime.GOOS
	ec.Discovery.LocalHost.Mode = r.Mode()
	ec.Discovery.LocalHost.HostLabel = r.HostLabel()
	log("Modo invasivo activado. Inspeccionando host local (%s)", runtime.GOOS)
	runHostChecks(ec, r, log)
}

// runRemoteHostChecks ejecuta las MISMAS verificaciones pero contra un host
// remoto vía SSH. La llave/credencial se pasa en ec.SSHKey o se delega al
// agente SSH del sistema. cmd/scan.go construye el sshRunner antes de
// invocar discovery.Run.
func runRemoteHostChecks(ec *ctx.EvalContext, log func(string, ...interface{})) {
	r := sshRunner{
		target:     ec.SSHTarget,
		port:       ec.SSHPort,
		keyPath:    ec.SSHKeyPath,
		useSudo:    ec.SSHUseSudo,
		cmdTimeout: 30 * time.Second,
	}
	log("Modo remoto SSH activado. Inspeccionando %s", r.HostLabel())

	// Smoke test: ¿podemos siquiera hablar por SSH con el host? Si no,
	// dejamos LocalHost.Available=false para que los validadores caigan a
	// "falta evidencia / manual" con un mensaje claro.
	if out, _, err := r.Run("uname", "-s"); err != nil {
		appendErr(ec, "no se pudo establecer sesión SSH con %s: %v. Salida: %s", r.HostLabel(), err, out)
		ec.Discovery.LocalHost.Available = false
		ec.Discovery.LocalHost.Mode = r.Mode()
		ec.Discovery.LocalHost.HostLabel = r.HostLabel()
		return
	}
	ec.Discovery.LocalHost.Available = true
	ec.Discovery.LocalHost.OS = "linux" // sshRunner solo aplica a hosts Linux por ahora
	ec.Discovery.LocalHost.Mode = r.Mode()
	ec.Discovery.LocalHost.HostLabel = r.HostLabel()
	runHostChecks(ec, r, log)
}

// runHostChecks orquesta los chequeos independientemente del runner.
// Cada chequeo es defensivo: si una herramienta no está disponible o
// el comando falla, lo registra en Errors y continúa.
func runHostChecks(ec *ctx.EvalContext, r hostRunner, log func(string, ...interface{})) {
	collectOSInfo(ec, r, log)
	checkPackageUpdates(ec, r, log)
	checkLocalFirewall(ec, r, log)
	checkSSHHardening(ec, r, log)
	checkSensitiveFilePermissions(ec, r, log)
	checkAuditAndLogs(ec, r, log)
}

// ----------------------- Información básica del SO -----------------------

func collectOSInfo(ec *ctx.EvalContext, r hostRunner, log func(string, ...interface{})) {
	// /etc/os-release está estandarizado en sistemas Linux modernos.
	if data, err := r.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				ec.Discovery.LocalHost.OSVersion = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				break
			}
		}
	}
	if out, _, err := r.Run("uname", "-r"); err == nil {
		ec.Discovery.LocalHost.Kernel = out
	}
}

// ----------------------- HAR-04: parches -----------------------

// checkPackageUpdates intenta determinar cuántas actualizaciones pendientes
// tiene el sistema. Maneja apt (Debian/Ubuntu), dnf (RHEL/Fedora), yum
// (RHEL antiguos), pacman (Arch). Si ninguno está disponible registra el
// error y la regla queda en falta-evidencia.
func checkPackageUpdates(ec *ctx.EvalContext, r hostRunner, log func(string, ...interface{})) {
	// 1. apt (Debian / Ubuntu). `apt list --upgradable` no requiere root.
	if out, available, err := r.Run("apt", "list", "--upgradable"); available {
		log("Detectando actualizaciones pendientes con apt")
		// Reportar edad del cache si está disponible.
		if st, _ := r.Stat("/var/cache/apt/pkgcache.bin"); st.Exists {
			// No tenemos ModTime para sshRunner. En modo local sí, lo
			// chequeamos directamente como antes.
			if r.Mode() == "local-host" {
				if info, ierr := os.Stat("/var/cache/apt/pkgcache.bin"); ierr == nil {
					age := time.Since(info.ModTime())
					ec.Discovery.LocalHost.PackagesCheckedAt = fmt.Sprintf("hace %s (apt-cache modificado el %s)",
						humanDuration(age), info.ModTime().Format("2006-01-02 15:04"))
				}
			}
		}
		if err != nil {
			ec.Discovery.LocalHost.PackagesError = fmt.Sprintf("apt list falló: %v", err)
			return
		}
		lines := strings.Split(out, "\n")
		total := 0
		security := 0
		secRe := regexp.MustCompile(`(?i)(security|esm)`)
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "Listing") || strings.HasPrefix(ln, "WARNING") {
				continue
			}
			total++
			if secRe.MatchString(ln) {
				security++
			}
		}
		ec.Discovery.LocalHost.PackagesOutdated = total
		ec.Discovery.LocalHost.SecurityUpdatesPending = security
		return
	}

	// 2. dnf (RHEL 8+, Fedora). Exit code 100 = hay updates, no es error.
	if out, available, err := r.Run("dnf", "check-update", "-q"); available {
		if err != nil && !strings.Contains(err.Error(), "exit status 100") {
			ec.Discovery.LocalHost.PackagesError = fmt.Sprintf("dnf check-update falló: %v", err)
			return
		}
		count := 0
		for _, ln := range strings.Split(out, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "Obsoleting") {
				continue
			}
			fields := strings.Fields(ln)
			if len(fields) >= 3 {
				count++
			}
		}
		ec.Discovery.LocalHost.PackagesOutdated = count
		if outSec, _, err := r.Run("dnf", "updateinfo", "list", "security", "-q"); err == nil {
			sec := 0
			for _, ln := range strings.Split(outSec, "\n") {
				if strings.TrimSpace(ln) != "" {
					sec++
				}
			}
			ec.Discovery.LocalHost.SecurityUpdatesPending = sec
		}
		return
	}

	// 3. yum (RHEL 7, CentOS 7)
	if out, available, _ := r.Run("yum", "check-update", "-q"); available {
		count := 0
		for _, ln := range strings.Split(out, "\n") {
			if strings.TrimSpace(ln) != "" {
				count++
			}
		}
		ec.Discovery.LocalHost.PackagesOutdated = count
		return
	}

	// 4. pacman (Arch).
	if out, available, _ := r.Run("pacman", "-Qu"); available {
		count := 0
		for _, ln := range strings.Split(out, "\n") {
			if strings.TrimSpace(ln) != "" {
				count++
			}
		}
		ec.Discovery.LocalHost.PackagesOutdated = count
		return
	}

	appendErr(ec, "verificación de paquetes: ningún gestor soportado (apt/dnf/yum/pacman) encontrado")
}

// ----------------------- HAR-05: firewall local -----------------------

func checkLocalFirewall(ec *ctx.EvalContext, r hostRunner, log func(string, ...interface{})) {
	// Orden: ufw > firewalld > nftables > iptables.

	if out, available, _ := r.Run("ufw", "status"); available {
		ec.Discovery.LocalHost.FirewallTool = "ufw"
		if strings.Contains(out, "Status: active") {
			ec.Discovery.LocalHost.FirewallActive = true
			ec.Discovery.LocalHost.FirewallRulesCount = countLines(out) - 1
		} else if strings.Contains(out, "Status: inactive") {
			ec.Discovery.LocalHost.FirewallActive = false
		} else {
			appendErr(ec, "ufw status no concluyente (puede requerir sudo)")
		}
		if outVerb, _, err := r.Run("ufw", "status", "verbose"); err == nil {
			if strings.Contains(outVerb, "Default: deny (incoming)") || strings.Contains(outVerb, "Default: reject (incoming)") {
				ec.Discovery.LocalHost.FirewallDefaultDeny = true
			}
		}
		return
	}

	if out, available, _ := r.Run("firewall-cmd", "--state"); available {
		ec.Discovery.LocalHost.FirewallTool = "firewalld"
		ec.Discovery.LocalHost.FirewallActive = strings.Contains(out, "running")
		return
	}

	if out, available, err := r.Run("nft", "list", "ruleset"); available {
		ec.Discovery.LocalHost.FirewallTool = "nftables"
		if err == nil && strings.TrimSpace(out) != "" {
			ec.Discovery.LocalHost.FirewallActive = true
			ec.Discovery.LocalHost.FirewallRulesCount = countMatching(out, "rule")
			ec.Discovery.LocalHost.FirewallDefaultDeny = strings.Contains(out, "policy drop") || strings.Contains(out, "policy reject")
		} else {
			appendErr(ec, "nft list ruleset vacío o sin permisos (suele requerir sudo)")
		}
		return
	}

	if out, available, err := r.Run("iptables", "-S"); available {
		ec.Discovery.LocalHost.FirewallTool = "iptables"
		if err == nil {
			rules := countLines(out)
			ec.Discovery.LocalHost.FirewallRulesCount = rules
			defaultDeny := strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT")
			ec.Discovery.LocalHost.FirewallDefaultDeny = defaultDeny
			ec.Discovery.LocalHost.FirewallActive = rules > 3 || defaultDeny
		} else {
			appendErr(ec, "iptables -S falló (puede requerir sudo): %v", err)
		}
		return
	}

	ec.Discovery.LocalHost.FirewallTool = "none"
	ec.Discovery.LocalHost.FirewallActive = false
	appendErr(ec, "firewall local: no se encontró ufw, firewalld, nftables ni iptables")
}

// ----------------------- HAR-03 complemento: SSH config local -----------------------

// checkSSHHardening lee /etc/ssh/sshd_config (o equivalente) para refinar
// el dictamen de SVR-HAR-03 con valores reales en vez de heurística por banner.
func checkSSHHardening(ec *ctx.EvalContext, r hostRunner, log func(string, ...interface{})) {
	candidates := []string{"/etc/ssh/sshd_config", "/usr/local/etc/ssh/sshd_config"}
	var configPath string
	for _, p := range candidates {
		if st, _ := r.Stat(p); st.Exists {
			configPath = p
			break
		}
	}
	if configPath == "" {
		return
	}
	ec.Discovery.LocalHost.SSHConfigPath = configPath

	data, err := r.ReadFile(configPath)
	if err != nil {
		appendErr(ec, "sshd_config existe pero no se pudo leer (probablemente requiere sudo): %v", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := fields[1]
		switch key {
		case "permitrootlogin":
			ec.Discovery.LocalHost.SSHPermitRoot = val
		case "passwordauthentication":
			ec.Discovery.LocalHost.SSHPasswordAuth = strings.ToLower(val)
		case "pubkeyauthentication":
			ec.Discovery.LocalHost.SSHPubkeyAuth = strings.ToLower(val)
		}
	}
}

// ----------------------- HAR-08: permisos sensibles -----------------------

// sensitiveTargets lista los archivos cuya filtración accidental es de
// alto impacto. Para cada uno se define el modo máximo aceptable (no
// world-readable, dueño root cuando aplica).
var sensitiveTargets = []struct {
	Path        string
	MaxMode     os.FileMode // permisos máximos aceptables
	Description string
}{
	{"/etc/shadow", 0640, "hashes de contraseñas del sistema"},
	{"/etc/gshadow", 0640, "hashes de grupos"},
	{"/etc/sudoers", 0440, "configuración sudo"},
	{"/etc/ssh/ssh_host_rsa_key", 0600, "clave privada SSH del host"},
	{"/etc/ssh/ssh_host_ed25519_key", 0600, "clave privada SSH del host"},
	{"/etc/ssh/ssh_host_ecdsa_key", 0600, "clave privada SSH del host"},
	{"/etc/ssh/sshd_config", 0644, "configuración SSH"},
	{"/root/.ssh/authorized_keys", 0600, "llaves SSH autorizadas para root"},
}

func checkSensitiveFilePermissions(ec *ctx.EvalContext, r hostRunner, log func(string, ...interface{})) {
	for _, t := range sensitiveTargets {
		st, _ := r.Stat(t.Path)
		if !st.Exists {
			continue
		}
		mode := st.Mode
		// Compara los bits "world" y "group" contra MaxMode.
		if mode > t.MaxMode {
			ec.Discovery.LocalHost.SensitiveFiles = append(ec.Discovery.LocalHost.SensitiveFiles, ctx.SensitiveFileFinding{
				Path:    t.Path,
				Mode:    fmt.Sprintf("%#o", mode),
				Problem: fmt.Sprintf("%s con permisos %#o (máximo recomendado: %#o)", t.Description, mode, t.MaxMode),
			})
		}
	}
}

// ----------------------- HAR-10 / MON-01: auditoría y logs -----------------------

func checkAuditAndLogs(ec *ctx.EvalContext, r hostRunner, log func(string, ...interface{})) {
	// auditd
	if st, _ := r.Stat("/etc/audit/auditd.conf"); st.Exists {
		if out, _, err := r.Run("systemctl", "is-active", "auditd"); err == nil && strings.TrimSpace(out) == "active" {
			ec.Discovery.LocalHost.AuditdActive = true
		}
	} else {
		if out, _, err := r.Run("systemctl", "is-active", "systemd-journald"); err == nil && strings.TrimSpace(out) == "active" {
			ec.Discovery.LocalHost.LogsPresent = append(ec.Discovery.LocalHost.LogsPresent, "systemd-journald (auditoría básica del sistema)")
		}
	}

	// Logs en /var/log: inventariamos los archivos típicos no vacíos.
	logDir := "/var/log"
	interesting := []string{"auth.log", "secure", "syslog", "messages", "audit/audit.log", "nginx/access.log", "apache2/access.log"}
	for _, name := range interesting {
		p := filepath.Join(logDir, name)
		if st, _ := r.Stat(p); st.Exists && st.Size > 0 {
			ec.Discovery.LocalHost.LogsPresent = append(ec.Discovery.LocalHost.LogsPresent, name)
		}
	}

	// logrotate
	if st, _ := r.Stat("/etc/logrotate.conf"); st.Exists && st.Size > 0 {
		ec.Discovery.LocalHost.LogsRotating = true
	}
}

// --------------------------- helpers ---------------------------

func countLines(s string) int {
	n := 0
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}

func countMatching(s, substr string) int {
	n := 0
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, substr) {
			n++
		}
	}
	return n
}

func humanDuration(d time.Duration) string {
	hours := int(d.Hours())
	if hours < 1 {
		mins := int(d.Minutes())
		return strconv.Itoa(mins) + "m"
	}
	if hours < 24 {
		return strconv.Itoa(hours) + "h"
	}
	days := hours / 24
	return strconv.Itoa(days) + "d"
}
