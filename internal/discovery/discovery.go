// Package discovery implementa el Módulo 2 (Descubrimiento) del programa cliente.
// Ejecuta verificaciones activas y pasivas sobre el entorno objetivo y guarda
// la evidencia recopilada en EvalContext.Discovery, que luego el módulo de
// Validación contrasta contra cada SVR.
package discovery

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	ctx "github.com/stagingshield/staging-shield/internal/context"
)

// Run ejecuta todas las fases de descubrimiento secuencialmente.
// Cada fase es defensiva: si falla, registra el error y continúa con las demás.
func Run(ec *ctx.EvalContext, verbose bool) {
	log := func(format string, args ...interface{}) {
		if verbose {
			fmt.Printf("[descubrimiento] "+format+"\n", args...)
		}
	}

	log("Iniciando descubrimiento sobre %s", ec.Target)

	resolveDNS(ec, log)
	scanPorts(ec, log)
	probeTLS(ec, log)
	probeHTTP(ec, log)
	checkAdminExposure(ec, log)
	probeAdminEndpoints(ec, log)
	checkLegacyServices(ec, log)
	checkProductionReachability(ec, log)
	// Importante: gatherGitContext debe correr antes que scanSecrets para
	// que cada hallazgo se pueda etiquetar con tracked / in-history.
	gatherGitContext(ec, log)
	scanSecrets(ec, log)
	scanEnvFiles(ec, log)
	scanEnvValueLeaks(ec, log)

	// Modo invasivo opt-in. Solo lee información sobre el host LOCAL donde
	// corre el cliente. Si el usuario no lo activó, salta esta fase entera
	// y los validadores de hardening de host devuelven su comportamiento
	// previo (manual / falta de evidencia).
	//
	// Si el usuario en cambio especificó --ssh-target, las verificaciones se
	// hacen contra el host remoto vía SSH. Ambos modos son mutuamente
	// excluyentes; si están ambos activos, --ssh-target gana (es más
	// específico) y advertimos.
	if ec.SSHTarget != "" {
		if ec.LocalHostScan {
			log("Aviso: --local-host-scan y --ssh-target activos simultáneamente. Usando --ssh-target.")
		}
		runRemoteHostChecks(ec, log)
	} else if ec.LocalHostScan {
		runLocalHostChecks(ec, log)
	}

	log("Descubrimiento completado")
}

// -------------------------- DNS --------------------------

func resolveDNS(ec *ctx.EvalContext, log func(string, ...interface{})) {
	if ec.Target == "" {
		return
	}
	log("Resolviendo DNS de %s", ec.Target)
	host := strings.TrimSpace(ec.Target)
	// Quitar puerto si lo trae
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		ec.Discovery.DNSError = err.Error()
		return
	}
	ec.Discovery.DNSResolved = ips
	if ec.IPAddress == "" && len(ips) > 0 {
		ec.IPAddress = ips[0]
		log("Usando IP resuelta: %s", ec.IPAddress)
	}
}

// -------------------------- Escaneo de puertos --------------------------

// commonPorts es la lista de puertos comúnmente expuestos que el cliente
// va a probar para detectar superficie no declarada por el responsable
// del entorno. La lista combina servicios web, bases de datos, paneles
// de administración y servicios heredados.
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443,
	445, 465, 587, 636, 873, 993, 995, 1433, 1521, 2049, 2375, 2376,
	3000, 3306, 3389, 4444, 4848, 5000, 5432, 5601, 5672, 5900, 5984,
	6379, 6443, 7000, 7001, 7474, 7687, 8000, 8008, 8080, 8081, 8086,
	8088, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418,
	10000, 11211, 15672, 25565, 27017, 27018, 50000,
}

// legacyPorts agrupa puertos asociados a protocolos heredados o inseguros.
// Su sola presencia abierta es una señal directa para SVR-HAR-09.
var legacyPorts = map[int]string{
	21:  "FTP (texto plano)",
	23:  "Telnet (texto plano)",
	25:  "SMTP sin TLS",
	69:  "TFTP (sin autenticación)",
	110: "POP3 sin TLS",
	111: "RPCBind (atacable, prefiere RPC sobre TLS)",
	139: "NetBIOS",
	143: "IMAP sin TLS",
	445: "SMB (frecuentemente vulnerable)",
	512: "rexec (heredado)",
	513: "rlogin (heredado)",
	514: "rsh (heredado)",
}

// adminPorts agrupa puertos típicos de paneles administrativos cuya
// exposición pública es un riesgo grave (SVR-NET-08, SVR-IAM-05).
var adminPorts = map[int]string{
	22:    "SSH",
	2375:  "Docker daemon (sin TLS)",
	2376:  "Docker daemon (TLS)",
	3000:  "Panel admin (Grafana/otros)",
	3389:  "RDP",
	4848:  "GlassFish admin",
	5601:  "Kibana",
	6443:  "Kubernetes API",
	7474:  "Neo4j browser",
	8080:  "Tomcat/Jenkins admin",
	8443:  "Panel admin sobre HTTPS",
	9090:  "Prometheus",
	9200:  "Elasticsearch",
	10000: "Webmin",
	15672: "RabbitMQ admin",
	50000: "SAP / Jenkins",
}

// scanPorts realiza un escaneo TCP connect contra commonPorts más los
// expected_ports declarados por el usuario. Se ejecuta en paralelo con
// pool acotado para no saturar la red local del evaluador.
func scanPorts(ec *ctx.EvalContext, log func(string, ...interface{})) {
	target := ec.IPAddress
	if target == "" && ec.Target != "" {
		target = ec.Target
	}
	if target == "" {
		log("Sin IP/hostname, se omite escaneo de puertos")
		return
	}

	log("Escaneando puertos sobre %s", target)

	// Unión de commonPorts + expected_ports (deduplicado)
	portSet := make(map[int]struct{})
	for _, p := range commonPorts {
		portSet[p] = struct{}{}
	}
	for _, p := range ec.ExpectedPorts {
		portSet[p] = struct{}{}
	}
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	const workers = 50
	var (
		mu   sync.Mutex
		open []ctx.PortFinding
		sem  = make(chan struct{}, workers)
		wg   sync.WaitGroup
	)
	timeout := 1500 * time.Millisecond

	for _, p := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return
			}
			banner := grabBanner(conn)
			conn.Close()
			mu.Lock()
			open = append(open, ctx.PortFinding{Port: port, Banner: banner})
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	ec.Discovery.OpenPorts = open

	// Calcular puertos inesperados / faltantes contra los declarados
	expected := make(map[int]bool)
	for _, p := range ec.ExpectedPorts {
		expected[p] = true
	}
	openSet := make(map[int]bool)
	bannerMap := make(map[int]string)
	for _, f := range open {
		openSet[f.Port] = true
		if f.Banner != "" {
			bannerMap[f.Port] = f.Banner
		}
	}
	ec.Discovery.Banners = bannerMap

	if len(ec.ExpectedPorts) > 0 {
		for _, p := range open {
			if !expected[p.Port] {
				ec.Discovery.UnexpectedPorts = append(ec.Discovery.UnexpectedPorts, p.Port)
			}
		}
		for _, p := range ec.ExpectedPorts {
			if !openSet[p] {
				ec.Discovery.MissingPorts = append(ec.Discovery.MissingPorts, p)
			}
		}
	}
	log("Puertos abiertos detectados: %d (inesperados: %d)", len(open), len(ec.Discovery.UnexpectedPorts))
}

// grabBanner intenta leer hasta el primer salto de línea o un máximo de bytes
// para identificar el servicio que escucha.
func grabBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	s := strings.TrimSpace(string(buf[:n]))
	// Recortar a una sola línea para que sea legible
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// -------------------------- TLS --------------------------

func probeTLS(ec *ctx.EvalContext, log func(string, ...interface{})) {
	host := strings.TrimSpace(ec.Target)
	if host == "" {
		return
	}
	log("Probando TLS sobre %s:443", host)

	addr := net.JoinHostPort(host, "443")
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Solo recopilamos evidencia; no confiamos por defecto
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		ec.Discovery.TLS = ctx.TLSFinding{Tested: true, Available: false, Error: err.Error()}
		return
	}
	defer conn.Close()
	st := conn.ConnectionState()
	finding := ctx.TLSFinding{
		Tested:      true,
		Available:   true,
		Version:     tlsVersionString(st.Version),
		CipherSuite: tls.CipherSuiteName(st.CipherSuite),
		IsTLS13:     st.Version == tls.VersionTLS13,
	}
	if len(st.PeerCertificates) > 0 {
		c := st.PeerCertificates[0]
		finding.CertSubject = c.Subject.String()
		finding.CertIssuer = c.Issuer.String()
		finding.NotAfter = c.NotAfter
		finding.IsExpired = time.Now().After(c.NotAfter)
	}
	ec.Discovery.TLS = finding
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// -------------------------- HTTP --------------------------

func probeHTTP(ec *ctx.EvalContext, log func(string, ...interface{})) {
	host := strings.TrimSpace(ec.Target)
	if host == "" {
		return
	}

	// Probar primero HTTPS, luego HTTP si no responde
	urls := []string{"https://" + host, "http://" + host}
	client := &http.Client{
		Timeout: 7 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// No seguir redirecciones para capturar headers reales
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, u := range urls {
		log("Probando HTTP sobre %s", u)
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "StagingShield/1.0")
		resp, err := client.Do(req)
		if err != nil {
			ec.Discovery.HTTPError = err.Error()
			continue
		}
		ec.Discovery.HTTPStatus = resp.StatusCode
		headers := make(map[string]string, len(resp.Header))
		for k, v := range resp.Header {
			headers[k] = strings.Join(v, ", ")
		}
		ec.Discovery.HTTPHeaders = headers
		ec.Discovery.HTTPError = ""
		resp.Body.Close()
		return
	}
}

// -------------------------- Exposición administrativa --------------------------

func checkAdminExposure(ec *ctx.EvalContext, log func(string, ...interface{})) {
	// Conjunto de puertos administrativos esperados como permitidos por el usuario
	allowed := make(map[int]bool)
	for _, raw := range ec.AdminInterfaces {
		raw = strings.TrimSpace(raw)
		var port int
		if _, err := fmt.Sscanf(raw, "%d", &port); err == nil && port > 0 {
			allowed[port] = true
		}
	}
	for _, f := range ec.Discovery.OpenPorts {
		if desc, ok := adminPorts[f.Port]; ok && !allowed[f.Port] {
			ec.Discovery.AdminExposed = append(ec.Discovery.AdminExposed, ctx.AdminFinding{
				Port:        f.Port,
				Description: desc,
			})
		}
	}
	if len(ec.Discovery.AdminExposed) > 0 {
		log("Interfaces administrativas potencialmente expuestas: %d", len(ec.Discovery.AdminExposed))
	}
}

// probeAdminEndpoints intenta una petición HEAD/GET sobre cada interfaz
// administrativa detectada para clasificar su comportamiento de
// autenticación. Esto convierte SVR-IAM-08 en automática: ya no requiere
// revisión humana en el caso común de paneles web (el más frecuente).
//
// Se considera AuthChallenge=true si:
//   - El status es 401, 403 o 407 (código clásico de "necesita credenciales").
//   - La respuesta trae header WWW-Authenticate (Basic/Bearer/Digest/etc).
//   - Hay redirect a una página de login (3xx + Location con "login"/"signin"/"auth").
//
// Se considera AuthChallenge=false si:
//   - Status 200/204/206 sin redirect a login y sin WWW-Authenticate.
//   - El servidor sirve contenido directamente.
//
// Para puertos no-HTTP (SSH=22, RDP=3389, DB=5432/3306/27017, Docker=2375,
// etc.) no se prueba HTTP — esos protocolos tienen su propia lógica de
// autenticación que el cliente no puede inspeccionar de forma genérica, y
// la mera existencia del puerto abierto a internet ya lo reporta NET-08.
// Para esos casos se deja AuthChallenge=false (asumimos exposición sin
// validación visible) para que IAM-08 los marque como riesgosos por defecto.
func probeAdminEndpoints(ec *ctx.EvalContext, log func(string, ...interface{})) {
	if len(ec.Discovery.AdminExposed) == 0 {
		return
	}
	host := strings.TrimSpace(ec.Target)
	if host == "" {
		host = ec.IPAddress
	}
	if host == "" {
		return
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Puertos típicamente HTTP/HTTPS donde el probe tiene sentido.
	httpPorts := map[int]bool{
		80: true, 443: true, 8080: true, 8443: true,
		9090: true, 9091: true, 9100: true, 9200: true,
		15672: true,                         // RabbitMQ admin
		8888:  true, 8000: true, 5601: true, // Kibana
		3000: true, 4000: true, // Grafana / dashboards
	}

	for i, af := range ec.Discovery.AdminExposed {
		if !httpPorts[af.Port] {
			ec.Discovery.AdminExposed[i].Probed = true
			ec.Discovery.AdminExposed[i].AuthChallenge = false
			ec.Discovery.AdminExposed[i].ProbeError = "puerto no-HTTP, validación de autenticación fuera de alcance del cliente"
			continue
		}

		// Probar HTTPS primero, después HTTP plano.
		schemes := []string{"https", "http"}
		if af.Port == 80 || af.Port == 8080 || af.Port == 8000 || af.Port == 3000 || af.Port == 4000 {
			schemes = []string{"http", "https"}
		}
		probed := false
		for _, sch := range schemes {
			url := fmt.Sprintf("%s://%s:%d/", sch, host, af.Port)
			log("Probando interfaz admin %s", url)
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "StagingShield/1.0")
			resp, err := client.Do(req)
			if err != nil {
				ec.Discovery.AdminExposed[i].ProbeError = err.Error()
				continue
			}
			ec.Discovery.AdminExposed[i].Probed = true
			ec.Discovery.AdminExposed[i].HTTPStatus = resp.StatusCode

			authChallenge := false
			if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 407 {
				authChallenge = true
			}
			if v := resp.Header.Get("WWW-Authenticate"); v != "" {
				authChallenge = true
			}
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				loc := strings.ToLower(resp.Header.Get("Location"))
				if strings.Contains(loc, "login") || strings.Contains(loc, "signin") ||
					strings.Contains(loc, "auth") || strings.Contains(loc, "sso") {
					authChallenge = true
				}
			}
			ec.Discovery.AdminExposed[i].AuthChallenge = authChallenge
			resp.Body.Close()
			probed = true
			break
		}
		if !probed {
			// Fallo total: ambos schemes dieron error. Lo dejamos como
			// no probado y IAM-08 lo reportará como falta de evidencia.
			ec.Discovery.AdminExposed[i].Probed = false
		}
	}
}

// -------------------------- Servicios heredados --------------------------

func checkLegacyServices(ec *ctx.EvalContext, log func(string, ...interface{})) {
	for _, f := range ec.Discovery.OpenPorts {
		if _, ok := legacyPorts[f.Port]; ok {
			ec.Discovery.LegacyServices = append(ec.Discovery.LegacyServices, f.Port)
		}
	}
	if len(ec.Discovery.LegacyServices) > 0 {
		log("Servicios heredados detectados: %v", ec.Discovery.LegacyServices)
	}
}

// -------------------------- Alcance hacia producción --------------------------

// checkProductionReachability hace pruebas TCP de muy bajo costo contra puertos
// representativos de los hosts marcados como producción. Si responden,
// existe una ruta sospechosa entre staging y producción.
func checkProductionReachability(ec *ctx.EvalContext, log func(string, ...interface{})) {
	if len(ec.ProductionRefs) == 0 {
		return
	}
	probePorts := []int{22, 80, 443, 3306, 5432, 6379, 27017}
	timeout := 1200 * time.Millisecond

	for _, host := range ec.ProductionRefs {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		reached := false
		for _, p := range probePorts {
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				reached = true
				break
			}
		}
		if reached {
			ec.Discovery.ProductionReachable = append(ec.Discovery.ProductionReachable, host)
		}
	}
	if len(ec.Discovery.ProductionReachable) > 0 {
		log("Hosts de producción alcanzables desde staging: %v", ec.Discovery.ProductionReachable)
	}
}

// -------------------------- Detección de secretos --------------------------

// secretPatterns son patrones representativos. Es deliberadamente conservador
// para minimizar falsos positivos; aun así se emite una severidad por patrón.
var secretPatterns = []struct {
	Name     string
	Re       *regexp.Regexp
	Severity string
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "alto"},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws(.{0,20})?(secret|access)?(.{0,20})?[\s:=]+[A-Za-z0-9/+=]{40}`), "alto"},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`), "alto"},
	{"Slack Token", regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,48}`), "alto"},
	{"Generic API Key", regexp.MustCompile(`(?i)(api[-_]?key|apikey|secret[-_]?key)[\s:="']+([A-Za-z0-9_\-]{20,})`), "medio"},
	// Bearer tokens: opaque tokens reales suelen ser de 32+ chars y JWTs son >100.
	// Subir el mínimo de 20 a 32 elimina casos como "Bearer invalid-token-for-test"
	// (22 chars) sin perder tokens reales. Ver fixtureMatchValues() para el filtro
	// adicional de palabras placeholder.
	{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{32,}`), "medio"},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN ((RSA|DSA|EC|OPENSSH|PGP) )?PRIVATE KEY-----`), "alto"},
	{"Postgres URL", regexp.MustCompile(`postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+`), "alto"},
	{"MySQL URL", regexp.MustCompile(`mysql://[^:\s]+:[^@\s]+@[^/\s]+`), "alto"},
	{"MongoDB URL", regexp.MustCompile(`mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+`), "alto"},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), "medio"},
	{"Password Assignment", regexp.MustCompile(`(?i)(password|passwd|pwd)[\s:="']+([^"'\s]{6,})`), "medio"},
}

// testPathFragments son fragmentos de ruta que indican código de test/fixture.
// Cuando el archivo escaneado está bajo cualquiera de estos directorios el
// hallazgo se marca como "fixture" y NO penaliza SVR-IAM-04. Esto evita el
// falso positivo histórico donde un literal como "Bearer invalid-token-for-test"
// dentro de un archivo .test.js disparaba alerta.
var testPathFragments = []string{
	"/test/", "/tests/", "/__tests__/", "/__test__/",
	"/spec/", "/specs/", "/__specs__/",
	"/e2e/", "/integration/", "/cypress/", "/playwright/",
	"/fixtures/", "/fixture/", "/__fixtures__/",
	"/mocks/", "/__mocks__/",
	"/testdata/", "/test-data/",
	"/examples/", "/example/", "/samples/",
}

// testFileSuffixes son patrones de nombre de archivo que indican test.
// Se evalúan sobre el nombre solo (no la ruta completa). El match es por
// substring case-insensitive: si el nombre contiene cualquier de estos
// fragmentos se considera test fixture.
var testFileSuffixes = []string{
	".test.", ".spec.",
	"_test.", "_spec.",
	".tests.", ".specs.",
	"-test.", "-spec.",
}

// placeholderTokens son palabras que, presentes dentro del valor matcheado por
// una regex de secreto, indican placeholder o dato de demostración y NO un
// secreto real. Se comparan en lowercase.
var placeholderTokens = []string{
	"invalid", "fake", "dummy", "example", "placeholder",
	"sample", "demo", "test", "mock", "stub",
	"replace", "your-", "your_", "yourtoken", "yourapikey",
	"changeme", "change-me", "change_me",
	"xxxx", "yyyy", "zzzz",
	"<token>", "<key>", "<secret>", "<password>",
	"todo", "fixme", "lorem",
	"abc123", "1234567890",
}

// isTestFixturePath devuelve true si el archivo en relPath debe tratarse como
// fixture/test y los hallazgos en él NO penalizan IAM-04.
// La ruta se normaliza a slash-forward para que el matcheo sea estable entre
// Windows ("test\\foo.js") y Linux ("test/foo.js").
func isTestFixturePath(relPath string) bool {
	norm := "/" + strings.ReplaceAll(relPath, "\\", "/")
	low := strings.ToLower(norm)
	for _, f := range testPathFragments {
		if strings.Contains(low, f) {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(relPath))
	for _, sfx := range testFileSuffixes {
		if strings.Contains(base, sfx) {
			return true
		}
	}
	return false
}

// looksLikePlaceholder devuelve true si el valor matcheado contiene una palabra
// indicativa de placeholder o demo (e.g. "Bearer invalid-token-for-test").
func looksLikePlaceholder(match string) bool {
	low := strings.ToLower(match)
	for _, tok := range placeholderTokens {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

// extsScanned define las extensiones que se inspeccionan para secretos.
var extsScanned = map[string]bool{
	".env": true, ".yml": true, ".yaml": true, ".json": true,
	".js": true, ".ts": true, ".py": true, ".go": true, ".java": true,
	".rb": true, ".php": true, ".sh": true, ".conf": true, ".config": true,
	".ini": true, ".toml": true, ".properties": true, ".xml": true,
}

// fileNamesScanned son nombres exactos que escanea aunque no tengan extensión.
var fileNamesScanned = map[string]bool{
	".env": true, "Dockerfile": true, "docker-compose.yml": true,
	"docker-compose.yaml": true,
}

// pathsSkipped son carpetas que jamás se inspeccionan para evitar gigabytes de
// dependencias.
var pathsSkipped = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "dist": true,
	"build": true, "target": true, "__pycache__": true, ".venv": true,
	"venv": true, ".idea": true, ".vscode": true,
}

func scanSecrets(ec *ctx.EvalContext, log func(string, ...interface{})) {
	if ec.RepoPath == "" {
		return
	}
	log("Escaneando secretos en %s", ec.RepoPath)

	const maxFileSize = 2 * 1024 * 1024 // 2 MiB
	const maxFiles = 10000
	count := 0

	// Conjuntos de tracking para etiquetar cada hallazgo según su estado
	// frente a git. Si git no está disponible, ambos quedan vacíos y los
	// validadores caen al comportamiento previo.
	tracked := make(map[string]bool, len(ec.Discovery.Git.TrackedFiles))
	for _, p := range ec.Discovery.Git.TrackedFiles {
		tracked[normalizeRel(p)] = true
	}
	inHistory := make(map[string]bool, len(ec.Discovery.Git.HistoryFiles))
	for _, p := range ec.Discovery.Git.HistoryFiles {
		inHistory[normalizeRel(p)] = true
	}

	_ = filepath.WalkDir(ec.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if pathsSkipped[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= maxFiles {
			return errors.New("límite de archivos alcanzado")
		}
		count++

		name := d.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if !extsScanned[ext] && !fileNamesScanned[name] {
			return nil
		}

		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(ec.RepoPath, path)
		relNorm := normalizeRel(rel)
		// Marcamos el archivo entero como fixture si está bajo test/, fixtures/,
		// examples/, etc. Así cada match heredado de él sale con IsFixture=true
		// y el validador IAM-04 puede excluirlos del cálculo punitivo, dejándolos
		// solo informativos.
		fileIsFixture := isTestFixturePath(rel)

		// Procesar línea por línea para reportar línea exacta
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			for _, pat := range secretPatterns {
				if loc := pat.Re.FindStringIndex(line); loc != nil {
					match := line[loc[0]:loc[1]]
					// Filtro adicional: incluso si el archivo no está en una
					// ruta de test, un literal con palabras "invalid", "fake",
					// "your-token-here", etc. dentro del valor matcheado es
					// señal fuerte de placeholder.
					isFixture := fileIsFixture || looksLikePlaceholder(match)
					match = redactSecret(match)
					ec.Discovery.SecretFindings = append(ec.Discovery.SecretFindings, ctx.SecretFinding{
						File:      rel,
						Line:      i + 1,
						Pattern:   pat.Name,
						Match:     match,
						Severity:  pat.Severity,
						Tracked:   tracked[relNorm],
						InHistory: inHistory[relNorm],
						IsFixture: isFixture,
					})
				}
			}
		}
		return nil
	})

	if len(ec.Discovery.SecretFindings) > 0 {
		realCount := 0
		fixtureCount := 0
		for _, f := range ec.Discovery.SecretFindings {
			if f.IsFixture {
				fixtureCount++
			} else {
				realCount++
			}
		}
		log("Hallazgos de secretos: %d reales, %d en archivos de test/ejemplo (no penalizan)", realCount, fixtureCount)
	}
}

// -------------------------- Contexto git --------------------------

// gatherGitContext consulta git para saber qué archivos están actualmente
// trackeados y cuáles aparecen en el historial (aunque hoy no existan).
// Esto es lo que le permite a los validadores distinguir un .env solo
// local (sin riesgo de exposición) de uno trackeado o filtrado en commits
// previos. Si git no está disponible o el repo no es git, deja Available
// en false y registra el motivo en Error.
func gatherGitContext(ec *ctx.EvalContext, log func(string, ...interface{})) {
	if ec.RepoPath == "" {
		return
	}
	// Validar que es un repo git
	if _, err := os.Stat(filepath.Join(ec.RepoPath, ".git")); err != nil {
		ec.Discovery.Git = ctx.GitContext{
			Available: false,
			Error:     "el repositorio no contiene .git/, no se puede inferir tracking",
		}
		log("git: repo sin .git/, evaluación de exposición caerá a presencia en disco")
		return
	}
	if _, err := exec.LookPath("git"); err != nil {
		ec.Discovery.Git = ctx.GitContext{
			Available: false,
			Error:     "binario 'git' no disponible en PATH del evaluador",
		}
		log("git: binario no encontrado en PATH; análisis git desactivado")
		return
	}

	gc := ctx.GitContext{Available: true}

	// Archivos trackeados hoy
	if out, err := runGit(ec.RepoPath, "ls-files"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				gc.TrackedFiles = append(gc.TrackedFiles, line)
			}
		}
	} else {
		gc.Error = "git ls-files falló: " + err.Error()
	}

	// Archivos que alguna vez existieron en el historial. Sirve para
	// detectar .env removidos pero recuperables desde commits previos.
	if out, err := runGit(ec.RepoPath,
		"log", "--all", "--pretty=format:", "--name-only", "--diff-filter=A"); err == nil {
		seen := make(map[string]struct{})
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, dup := seen[line]; dup {
				continue
			}
			seen[line] = struct{}{}
			gc.HistoryFiles = append(gc.HistoryFiles, line)
		}
	}

	// ¿Existe .gitignore?
	if _, err := os.Stat(filepath.Join(ec.RepoPath, ".gitignore")); err == nil {
		gc.GitignoreSeen = true
	}

	ec.Discovery.Git = gc
	log("git: %d trackeados, %d en historial, .gitignore=%v",
		len(gc.TrackedFiles), len(gc.HistoryFiles), gc.GitignoreSeen)
}

// runGit ejecuta git con un timeout corto y devuelve stdout. Falla rápido
// si git tarda más de 10s (por ejemplo si el repo es enorme).
func runGit(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// -------------------------- Análisis de archivos .env --------------------------

// envFilePatterns son los nombres que el validador SVR-IAM-07 considera
// archivos de variables de entorno. La lista cubre las convenciones más
// comunes (Node, Python dotenv, Vite, Next.js, Rails, Laravel).
var envFilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\.env$`),
	regexp.MustCompile(`^\.env\.[A-Za-z0-9_.-]+$`),
}

// scanEnvFiles detecta cada .env / .env.* presente en el repositorio o en el
// historial git, y describe su estado de tracking. La verificación se separa
// del scan de secretos para permitirle a SVR-IAM-07 razonar sobre la
// existencia de los archivos como tales, incluso cuando no contienen
// secretos detectables por regex (por ejemplo, llaves de API arbitrarias
// que no encajan en ningún patrón).
func scanEnvFiles(ec *ctx.EvalContext, log func(string, ...interface{})) {
	if ec.RepoPath == "" {
		return
	}

	// Conjunto consolidado: archivos en disco + trackeados + en historial.
	// Cada archivo aparece una sola vez en el resultado final.
	candidates := make(map[string]*ctx.EnvFileFinding)

	add := func(rel string) *ctx.EnvFileFinding {
		rel = normalizeRel(rel)
		if !isEnvFile(rel) {
			return nil
		}
		if f, ok := candidates[rel]; ok {
			return f
		}
		f := &ctx.EnvFileFinding{Path: rel}
		candidates[rel] = f
		return f
	}

	// 1. Archivos en disco
	_ = filepath.WalkDir(ec.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if pathsSkipped[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(ec.RepoPath, path)
		add(rel)
		return nil
	})

	// 2. Archivos trackeados por git (capturan los que están en disco
	//    pero también permiten detectar trackeo aunque WalkDir los haya
	//    omitido por filtros).
	for _, p := range ec.Discovery.Git.TrackedFiles {
		if f := add(p); f != nil {
			f.Tracked = true
		}
	}

	// 3. Archivos en historial de git (caso crítico: .env borrado pero
	//    recuperable desde commits anteriores, lo cual sigue siendo
	//    exposición de secretos).
	for _, p := range ec.Discovery.Git.HistoryFiles {
		if f := add(p); f != nil {
			f.InHistory = true
		}
	}

	// 4. Estado de .gitignore: marca cada candidato como ignorado o no.
	//    Esto distingue al developer cuidadoso (gitignored) del descuidado
	//    (existe pero no está ignorado, riesgo latente de commit accidental).
	if ec.Discovery.Git.Available {
		for path, f := range candidates {
			f.Gitignored = checkGitignored(ec.RepoPath, path)
		}
	}

	// 5. ¿El archivo contenía secretos detectables? Esto refuerza la
	//    severidad cuando además está trackeado o en historial.
	for _, sec := range ec.Discovery.SecretFindings {
		rel := normalizeRel(sec.File)
		if f, ok := candidates[rel]; ok {
			f.HasSecrets = true
		}
	}

	for _, f := range candidates {
		ec.Discovery.EnvFiles = append(ec.Discovery.EnvFiles, *f)
	}
	if len(ec.Discovery.EnvFiles) > 0 {
		log("Archivos .env detectados: %d", len(ec.Discovery.EnvFiles))
	}
}

func isEnvFile(rel string) bool {
	base := filepath.Base(rel)
	for _, re := range envFilePatterns {
		if re.MatchString(base) {
			return true
		}
	}
	return false
}

// checkGitignored consulta a git si una ruta sería ignorada por .gitignore.
// `git check-ignore` devuelve exit code 0 si la ruta está ignorada y 1 si
// no, así que tratamos cualquier exit no-cero como "no ignorada".
func checkGitignored(repo, rel string) bool {
	cmd := exec.Command("git", "check-ignore", "-q", rel)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd.Run() == nil
}

// normalizeRel deja rutas con separador "/" para comparar entre Windows y *nix.
func normalizeRel(p string) string {
	return filepath.ToSlash(strings.TrimPrefix(p, "./"))
}

// redactSecret oculta la mayor parte del valor para no incluir secretos reales
// dentro del reporte que se va a guardar localmente.
func redactSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	keep := 4
	return s[:keep] + strings.Repeat("*", len(s)-keep*2) + s[len(s)-keep:]
}

// -------------------------- Cruce .env ↔ código --------------------------

// lowSignalValues son valores que, aunque aparezcan en un .env, no tienen
// suficiente especificidad para buscarlos en código sin generar ruido masivo.
var lowSignalValues = map[string]bool{
	"true": true, "false": true, "null": true, "nil": true,
	"localhost": true, "127.0.0.1": true, "0.0.0.0": true,
	"development": true, "production": true, "staging": true,
	"test": true, "debug": true, "info": true, "warn": true, "warning": true, "error": true,
	"yes": true, "no": true, "on": true, "off": true,
	"utf-8": true, "utf8": true,
}

var allDigits = regexp.MustCompile(`^\d+$`)

// isLowSignalValue devuelve true para valores que producirían demasiados
// falsos positivos: muy cortos, puramente numéricos o palabras genéricas.
func isLowSignalValue(v string) bool {
	if len(v) < 8 {
		return true
	}
	if allDigits.MatchString(v) {
		return true
	}
	return lowSignalValues[strings.ToLower(v)]
}

type envEntry struct {
	key     string
	envFile string
}

// parseEnvFile lee un archivo .env y devuelve un mapa value→[]envEntry.
// Soporta KEY=VALUE, KEY="VALUE" y KEY='VALUE'. Ignora comentarios e inline comments.
func parseEnvFile(path, relPath string) map[string][]envEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	result := make(map[string][]envEntry)
	seen := make(map[string]bool) // key+value para deduplicar si el mismo pair aparece dos veces

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Cortar comentario inline solo si hay espacio antes del #
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eqIdx])
		val := strings.TrimSpace(line[eqIdx+1:])

		// Quitar comillas envolventes
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}

		if isLowSignalValue(val) {
			continue
		}
		dedup := key + "\x00" + val
		if seen[dedup] {
			continue
		}
		seen[dedup] = true
		result[val] = append(result[val], envEntry{key: key, envFile: relPath})
	}
	return result
}

// scanEnvValueLeaks cruza los valores declarados en archivos .env con el
// código fuente para detectar hardcodeos directos. Se ejecuta después de
// scanEnvFiles y gatherGitContext.
func scanEnvValueLeaks(ec *ctx.EvalContext, log func(string, ...interface{})) {
	if ec.RepoPath == "" {
		return
	}

	// Mapas de tracking (mismo patrón que scanSecrets).
	tracked := make(map[string]bool, len(ec.Discovery.Git.TrackedFiles))
	for _, p := range ec.Discovery.Git.TrackedFiles {
		tracked[normalizeRel(p)] = true
	}
	inHistory := make(map[string]bool, len(ec.Discovery.Git.HistoryFiles))
	for _, p := range ec.Discovery.Git.HistoryFiles {
		inHistory[normalizeRel(p)] = true
	}

	// Construir mapa value → []envEntry desde los .env presentes en disco.
	// Los que solo están en historial git no se pueden leer fácilmente.
	valueToEntries := make(map[string][]envEntry)
	envFilePaths := make(map[string]bool) // rutas normalizadas de los propios .env
	for _, ef := range ec.Discovery.EnvFiles {
		absPath := filepath.Join(ec.RepoPath, filepath.FromSlash(ef.Path))
		if _, err := os.Stat(absPath); err != nil {
			continue // no está en disco
		}
		envFilePaths[normalizeRel(ef.Path)] = true
		for val, entries := range parseEnvFile(absPath, ef.Path) {
			valueToEntries[val] = append(valueToEntries[val], entries...)
		}
	}

	if len(valueToEntries) == 0 {
		log("Cruce .env↔código: sin valores de .env para comparar")
		return
	}
	log("Cruce .env↔código: buscando %d valores distintos del .env en código fuente", len(valueToEntries))

	const maxFileSize = 2 * 1024 * 1024
	const maxFiles = 10000
	count := 0

	// Conjunto de findings para deduplicar (key+envFile+leakFile+line).
	type findingKey struct {
		key, envFile, leakFile string
		line                   int
	}
	emitted := make(map[findingKey]bool)

	_ = filepath.WalkDir(ec.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if pathsSkipped[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= maxFiles {
			return errors.New("límite de archivos alcanzado")
		}
		count++

		name := d.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if !extsScanned[ext] && !fileNamesScanned[name] {
			return nil
		}

		rel, _ := filepath.Rel(ec.RepoPath, path)
		relNorm := normalizeRel(rel)

		// No buscar el valor dentro de su propio .env
		if envFilePaths[relNorm] {
			return nil
		}

		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		fileIsFixture := isTestFixturePath(rel)
		lines := strings.Split(string(data), "\n")

		for val, entries := range valueToEntries {
			for i, line := range lines {
				if !strings.Contains(line, val) {
					continue
				}
				isFixture := fileIsFixture || looksLikePlaceholder(val)
				for _, entry := range entries {
					fk := findingKey{entry.key, entry.envFile, relNorm, i + 1}
					if emitted[fk] {
						continue
					}
					emitted[fk] = true
					ec.Discovery.EnvValueLeaks = append(ec.Discovery.EnvValueLeaks, ctx.EnvValueLeakFinding{
						Key:          entry.key,
						EnvFile:      entry.envFile,
						LeakFile:     rel,
						Line:         i + 1,
						ValuePreview: redactSecret(val),
						IsFixture:    isFixture,
						Tracked:      tracked[relNorm],
						InHistory:    inHistory[relNorm],
					})
				}
			}
		}
		return nil
	})

	if len(ec.Discovery.EnvValueLeaks) > 0 {
		real, fixture := 0, 0
		for _, f := range ec.Discovery.EnvValueLeaks {
			if f.IsFixture {
				fixture++
			} else {
				real++
			}
		}
		log("Valores del .env hardcodeados en código: %d reales, %d en archivos test/ejemplo (no penalizan)", real, fixture)
	}
}
