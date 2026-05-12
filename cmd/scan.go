package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stagingshield/staging-shield/internal/config"
	ctx "github.com/stagingshield/staging-shield/internal/context"
	"github.com/stagingshield/staging-shield/internal/discovery"
	"github.com/stagingshield/staging-shield/internal/report"
	"github.com/stagingshield/staging-shield/internal/review"
	"github.com/stagingshield/staging-shield/internal/rules"
	"github.com/stagingshield/staging-shield/internal/scoring"
	"github.com/stagingshield/staging-shield/internal/storage"
)

// Flags del subcomando scan
var (
	scanConfigPath  string
	scanEnvName     string
	scanStack       string
	scanDomain      string
	scanIP          string
	scanPorts       []int
	scanRepo        string
	scanProdRefs    []string
	scanAdminPorts  []string
	scanReviewFile  string
	scanHTMLOut     string
	scanJSONHistory string
	scanHistoryDir  string
	scanNoColor     bool
	scanVerbose     bool
	scanNoSave      bool
	scanFailOnNoApt bool
	scanLocalHost   bool
	scanSSHTarget   string
	scanSSHKey      string
	scanSSHPort     int
	scanSSHSudo     bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Ejecuta una evaluación completa del entorno de preproducción",
	Long: `El comando scan ejecuta los cinco módulos del modelo en orden:

  1. Entrada       — carga config (YAML y/o flags) y construye el contexto.
  2. Descubrimiento — DNS, puertos, TLS, HTTP, secretos, prod, admin, legacy,
                     contexto git (tracked / historial / .gitignore).
  3. Validación    — aplica las 36 SVR contra la evidencia recolectada.
  3b. Revisión     — si --review está presente, sobreescribe los resultados
                     de las reglas manuales y de falta-evidencia con los
                     veredictos humanos del archivo YAML proporcionado.
  4. Scoring       — calcula score global, score por dominio y aptitud.
  5. Reporte       — emite consola (siempre) + HTML/JSON opcionales.

El archivo --review puede generarse desde el centro de revisión del reporte
HTML (botón "Exportar revisión") o escribirse a mano. Su formato:

  reviewer: "Nombre del Evaluador"
  timestamp: 2026-04-28T14:00:00Z
  verdicts:
    SVR-NET-02:
      status: cumple                  # cumple | cumple_parcial | no_cumple | no_aplica
      evidence: "Justificación de la decisión humana."

Si no se proporciona --config, todos los datos del entorno deben venir por flags.
Si se proporciona --config, los flags lo sobreescriben campo a campo.`,
	RunE: runScan,
}

func init() {
	f := scanCmd.Flags()
	f.StringVarP(&scanConfigPath, "config", "c", "", "Ruta a archivo YAML de configuración del entorno")
	f.StringVarP(&scanEnvName, "name", "n", "", "Nombre del entorno (p.ej. 'staging-app-pagos')")
	f.StringVarP(&scanStack, "stack", "s", "", "Tipo de stack: web, api, container, k8s, etc. (default: web)")
	f.StringVarP(&scanDomain, "domain", "d", "", "Dominio objetivo (con o sin esquema)")
	f.StringVar(&scanIP, "ip", "", "IP del servidor objetivo")
	f.IntSliceVarP(&scanPorts, "ports", "p", nil, "Lista de puertos esperados, p.ej. 80,443,8080")
	f.StringVarP(&scanRepo, "repo", "r", "", "Ruta local al repositorio del proyecto (para detección de secretos)")
	f.StringSliceVar(&scanProdRefs, "prod-refs", nil, "IPs/hosts de producción (para validar aislamiento)")
	f.StringSliceVar(&scanAdminPorts, "admin-interfaces", nil, "Puertos/rutas administrativos esperados, p.ej. 9090,/admin")
	f.StringVar(&scanReviewFile, "review", "", "Archivo YAML con veredictos manuales (exportado desde el reporte HTML o escrito a mano)")
	f.StringVar(&scanHTMLOut, "html-out", "", "Archivo de salida HTML (opcional)")
	f.StringVar(&scanJSONHistory, "json-out", "", "Archivo JSON adicional de salida (opcional, además del historial)")
	f.StringVar(&scanHistoryDir, "history-dir", "", "Directorio de historial (default: ~/.staging-shield/history)")
	f.BoolVar(&scanNoColor, "no-color", false, "Desactiva ANSI colors en salida de consola")
	f.BoolVarP(&scanVerbose, "verbose", "v", false, "Muestra trazas detalladas de descubrimiento")
	f.BoolVar(&scanNoSave, "no-save", false, "No guardar snapshot de historial en disco")
	f.BoolVar(&scanFailOnNoApt, "fail-on-noapt", false, "Devuelve exit code 2 si Apto=0 (útil en CI/CD)")
	f.BoolVar(&scanLocalHost, "local-host-scan", false,
		"ADVERTENCIA: Activa verificaciones INVASIVAS sobre el host LOCAL donde corre el cliente. "+
			"Lee lista de paquetes, configuración de SSH, firewall local, permisos de archivos sensibles y estado de logs. "+
			"Solo tiene sentido cuando el equipo donde corre el cliente ES el host de staging (típico en CI/CD o auditoría on-host). "+
			"NO inspecciona hosts remotos. Habilita automatización de SVR-HAR-04, HAR-05, HAR-08, HAR-10 y MON-01.")

	// Modo remoto SSH: misma cobertura que --local-host-scan pero contra un
	// host remoto. Pensado para CI/CD que corra fuera del servidor de staging.
	f.StringVar(&scanSSHTarget, "ssh-target", "",
		"Activa el modo remoto: el cliente abre una sesión SSH al host indicado (formato: user@host) "+
			"y ejecuta los mismos chequeos del modo invasivo sobre él. Mutuamente excluyente con --local-host-scan.")
	f.IntVar(&scanSSHPort, "ssh-port", 22, "Puerto SSH del host remoto.")
	f.StringVar(&scanSSHKey, "ssh-key", "",
		"Ruta a llave privada para autenticarse contra --ssh-target. "+
			"Si está vacío y existe STAGING_SHIELD_SSH_KEY como variable de entorno con el contenido de la llave, "+
			"se escribe a un archivo temporal (modo 0600) y se usa esa ruta (útil para CI/CD). "+
			"Si nada de eso está presente, se delega al agente ssh-agent o ~/.ssh por defecto.")
	f.BoolVar(&scanSSHSudo, "ssh-sudo", false,
		"Prefijar con 'sudo -n' los comandos que requieren privilegios (iptables, lectura de /etc/shadow, etc.). "+
			"Requiere que la cuenta SSH tenga NOPASSWD configurado para esos comandos en /etc/sudoers.")
}

func runScan(cmd *cobra.Command, args []string) error {
	// 1. ENTRADA --------------------------------------------------------
	ec, err := buildContextFromFlagsAndConfig()
	if err != nil {
		return fmt.Errorf("entrada inválida: %w", err)
	}

	if scanVerbose {
		fmt.Printf("[entrada] Entorno=%s Target=%s IP=%s Repo=%s\n",
			ec.EnvironmentName, ec.Target, ec.IPAddress, ec.RepoPath)
	}

	// Advertencia visible al usuario cuando se activó algún modo invasivo.
	// El mensaje aparece SIEMPRE (no solo en --verbose) para que sea
	// imposible activar el modo por accidente sin notarlo.
	if ec.SSHTarget != "" {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "============================================================")
		fmt.Fprintln(os.Stderr, "  MODO REMOTO SSH ACTIVADO (verificaciones invasivas)")
		fmt.Fprintln(os.Stderr, "============================================================")
		fmt.Fprintf(os.Stderr, "Inspeccionando host remoto: %s\n", ec.SSHTarget)
		if ec.SSHUseSudo {
			fmt.Fprintln(os.Stderr, "Modo sudo: comandos privilegiados con 'sudo -n'")
		}
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "El cliente abrirá una sesión SSH y ejecutará comandos para")
		fmt.Fprintln(os.Stderr, "leer estado de paquetes, configuración de SSH del host,")
		fmt.Fprintln(os.Stderr, "firewall, permisos de archivos sensibles, auditd y logs.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Asegúrese de que el host objetivo es EL CORRECTO. No use este")
		fmt.Fprintln(os.Stderr, "modo contra producción si su intención es evaluar staging.")
		fmt.Fprintln(os.Stderr, "============================================================")
		fmt.Fprintln(os.Stderr, "")
	} else if ec.LocalHostScan {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "============================================================")
		fmt.Fprintln(os.Stderr, "  MODO LOCAL-HOST-SCAN ACTIVADO (verificaciones invasivas)")
		fmt.Fprintln(os.Stderr, "============================================================")
		fmt.Fprintln(os.Stderr, "Este modo lee información sensible del equipo donde corre")
		fmt.Fprintln(os.Stderr, "el cliente:")
		fmt.Fprintln(os.Stderr, "  - Lista de paquetes y actualizaciones pendientes (apt/dnf/etc.)")
		fmt.Fprintln(os.Stderr, "  - Estado del firewall local (ufw, firewalld, iptables)")
		fmt.Fprintln(os.Stderr, "  - Configuración de SSH (/etc/ssh/sshd_config)")
		fmt.Fprintln(os.Stderr, "  - Permisos de archivos sensibles (/etc/shadow, llaves SSH)")
		fmt.Fprintln(os.Stderr, "  - Estado de auditd / journald y logs en /var/log")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "NUNCA inspecciona hosts remotos. Solo tiene sentido cuando")
		fmt.Fprintln(os.Stderr, "este equipo ES el host de staging (CI/CD, auditoría on-host).")
		fmt.Fprintln(os.Stderr, "============================================================")
		fmt.Fprintln(os.Stderr, "")
	}

	// 2. DESCUBRIMIENTO -------------------------------------------------
	discovery.Run(ec, scanVerbose)

	// 3. VALIDACIÓN -----------------------------------------------------
	rules.Validate(ec)

	// 3b. REVISIÓN MANUAL (opcional) -------------------------------------
	// Si el evaluador proporcionó un archivo de revisión, sobreescribimos
	// los resultados de las reglas manuales o sin evidencia con el
	// veredicto humano. Esto cierra la brecha entre la postura técnica y la
	// postura organizacional, y hace que las 13+ reglas manuales del
	// catálogo dejen de quedar fuera del cálculo.
	if scanReviewFile != "" {
		rev, err := review.Load(scanReviewFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Aviso: no se pudo cargar revisión manual (%v). Se continúa sin ella.\n", err)
		} else {
			n, unknown := review.Apply(ec.Results, rev)
			if scanVerbose {
				fmt.Printf("[revisión] %d veredictos aplicados desde %s\n", n, scanReviewFile)
			}
			if len(unknown) > 0 {
				fmt.Fprintf(os.Stderr, "Aviso: el archivo de revisión menciona IDs no encontrados: %s\n", strings.Join(unknown, ", "))
			}
		}
	}

	// 4. SCORING --------------------------------------------------------
	stats := scoring.Compute(ec, scoring.DefaultDomainWeights())

	// 5. REPORTE --------------------------------------------------------
	useColor := !scanNoColor && isTerminal(os.Stdout)
	report.PrintConsole(ec, stats, useColor)

	if scanHTMLOut != "" {
		if err := report.WriteHTML(scanHTMLOut, ec, stats); err != nil {
			fmt.Fprintf(os.Stderr, "Aviso: no se pudo escribir HTML (%v)\n", err)
		} else {
			fmt.Printf("\n📄 Reporte HTML: %s\n", scanHTMLOut)
		}
	}

	// Persistir historial (cumple SVR-MON-05: corridas comparables)
	if !scanNoSave {
		histDir := scanHistoryDir
		if histDir == "" {
			histDir = storage.DefaultDir()
		}
		if path, err := storage.Save(histDir, ec, stats); err != nil {
			fmt.Fprintf(os.Stderr, "Aviso: no se pudo guardar snapshot (%v)\n", err)
		} else if scanVerbose {
			fmt.Printf("[storage] snapshot: %s\n", path)
		}
	}

	// JSON de salida adicional (útil para integración CI)
	if scanJSONHistory != "" {
		dir := scanJSONHistory
		// Si se pasó un archivo, escribir a su directorio
		if !strings.HasSuffix(dir, string(os.PathSeparator)) {
			// tratamos scanJSONHistory como ruta de archivo: usar Save y renombrar es complejo;
			// más simple: escribir directamente.
			if err := writeJSONExport(scanJSONHistory, ec, stats); err != nil {
				fmt.Fprintf(os.Stderr, "Aviso: no se pudo escribir JSON (%v)\n", err)
			} else {
				fmt.Printf("📦 Export JSON: %s\n", scanJSONHistory)
			}
		}
	}

	// Exit code 2 si Apto=0 y se pidió fail-on-noapt (para integración CI/CD)
	if scanFailOnNoApt && !stats.Apto {
		os.Exit(2)
	}

	return nil
}

// buildContextFromFlagsAndConfig combina el archivo YAML (si existe) con los
// flags de la CLI. Los flags tienen prioridad sobre el archivo.
func buildContextFromFlagsAndConfig() (*ctx.EvalContext, error) {
	if scanConfigPath != "" {
		ec, err := config.Load(scanConfigPath)
		if err != nil {
			return nil, err
		}
		// Aplicar overrides de flags
		if scanEnvName != "" {
			ec.EnvironmentName = scanEnvName
		}
		if scanStack != "" {
			ec.StackType = scanStack
		}
		if scanDomain != "" {
			ec.Target = strings.TrimPrefix(strings.TrimPrefix(scanDomain, "https://"), "http://")
		}
		if scanIP != "" {
			ec.IPAddress = scanIP
		}
		if len(scanPorts) > 0 {
			ec.ExpectedPorts = scanPorts
		}
		if scanRepo != "" {
			ec.RepoPath = scanRepo
		}
		if len(scanProdRefs) > 0 {
			ec.ProductionRefs = scanProdRefs
		}
		if len(scanAdminPorts) > 0 {
			ec.AdminInterfaces = scanAdminPorts
		}
		if scanLocalHost {
			ec.LocalHostScan = true
		}
		if scanSSHTarget != "" {
			ec.SSHTarget = scanSSHTarget
		}
		if scanSSHPort != 0 && scanSSHPort != 22 {
			ec.SSHPort = scanSSHPort
		}
		if scanSSHKey != "" {
			ec.SSHKeyPath = scanSSHKey
		}
		if scanSSHSudo {
			ec.SSHUseSudo = true
		}
		// Resolver llave SSH desde la variable de entorno cuando aplique.
		// Esto es lo que un pipeline de CI/CD necesita: pasar el contenido
		// de la llave como secret de la plataforma y que el cliente la
		// materialice a un temp file con permisos 0600.
		if err := resolveSSHKeyFromEnv(ec); err != nil {
			return nil, fmt.Errorf("STAGING_SHIELD_SSH_KEY: %w", err)
		}
		return ec, nil
	}

	// Sin archivo: construir desde flags exclusivamente
	if scanEnvName == "" {
		return nil, fmt.Errorf("debe proporcionar --name o --config")
	}
	if scanDomain == "" && scanIP == "" {
		return nil, fmt.Errorf("debe proporcionar --domain o --ip (o --config)")
	}
	stack := scanStack
	if stack == "" {
		stack = "web"
	}
	ec, err := config.BuildFromFlags(scanEnvName, stack, scanDomain, scanIP, scanPorts, scanRepo, scanProdRefs)
	if err != nil {
		return nil, err
	}
	if len(scanAdminPorts) > 0 {
		ec.AdminInterfaces = scanAdminPorts
	}
	if scanLocalHost {
		ec.LocalHostScan = true
	}
	if scanSSHTarget != "" {
		ec.SSHTarget = scanSSHTarget
	}
	if scanSSHPort != 0 && scanSSHPort != 22 {
		ec.SSHPort = scanSSHPort
	}
	if scanSSHKey != "" {
		ec.SSHKeyPath = scanSSHKey
	}
	if scanSSHSudo {
		ec.SSHUseSudo = true
	}
	if err := resolveSSHKeyFromEnv(ec); err != nil {
		return nil, fmt.Errorf("STAGING_SHIELD_SSH_KEY: %w", err)
	}
	return ec, nil
}

// resolveSSHKeyFromEnv materializa la llave privada desde la variable de
// entorno STAGING_SHIELD_SSH_KEY si está presente y no se proporcionó
// --ssh-key. Esto es el patrón estándar para CI/CD: el secret manager
// inyecta el contenido completo de la llave (incluyendo BEGIN/END lines)
// y el cliente lo escribe a un archivo temp con modo 0600.
//
// La llave temporal vive solo durante el scan: no se borra explícitamente
// porque el OS limpia /tmp y porque limpiarla podría borrar la llave del
// usuario si por error puso ahí la ruta. El usuario es responsable de
// asegurar que la variable de entorno no quede expuesta tras el scan.
func resolveSSHKeyFromEnv(ec *ctx.EvalContext) error {
	if ec.SSHTarget == "" {
		return nil // sin target, nada que hacer
	}
	if ec.SSHKeyPath != "" {
		return nil // ya hay ruta explícita
	}
	keyContent := os.Getenv("STAGING_SHIELD_SSH_KEY")
	if keyContent == "" {
		return nil // ni env ni flag: el sshRunner usará ssh-agent o ~/.ssh
	}
	// Escribir a un archivo temp con permisos restrictivos.
	tmp, err := os.CreateTemp("", "staging-shield-ssh-*.key")
	if err != nil {
		return fmt.Errorf("no se pudo crear archivo temp: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("no se pudo cambiar permisos del archivo temp: %w", err)
	}
	// La llave puede no terminar en \n; ssh es tolerante pero forzamos por seguridad.
	if !strings.HasSuffix(keyContent, "\n") {
		keyContent += "\n"
	}
	if _, err := tmp.WriteString(keyContent); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("no se pudo escribir la llave al archivo temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("no se pudo cerrar el archivo temp: %w", err)
	}
	ec.SSHKeyPath = tmp.Name()
	return nil
}

// writeJSONExport escribe un export JSON en formato similar al historial pero
// en una ruta arbitraria (independiente del directorio de historial).
func writeJSONExport(path string, ec *ctx.EvalContext, stats scoring.Stats) error {
	// Reutilizamos storage.Save indirectamente: copiamos el snapshot al path indicado.
	// Como Save genera nombre automático, replicamos la lógica aquí en pequeño.
	dir := "."
	tmp, err := storage.Save(os.TempDir(), ec, stats)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	_ = dir // silenciar
	return os.WriteFile(path, data, 0o644)
}
