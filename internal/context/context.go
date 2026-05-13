// Package context define las estructuras centrales compartidas entre todos los
// módulos del programa: SVR, estados de cumplimiento, severidades, contexto de
// evaluación y reporte final.
package context

import "time"

// Severity representa el nivel de severidad de una SVR.
// Se mapea directamente al peso w_i del modelo de scoring.
type Severity int

const (
	SevBaja  Severity = 1
	SevMedia Severity = 2
	SevAlta  Severity = 3
)

func (s Severity) String() string {
	switch s {
	case SevAlta:
		return "Alta"
	case SevMedia:
		return "Media"
	case SevBaja:
		return "Baja"
	default:
		return "Desconocida"
	}
}

// ComplianceStatus representa el resultado de evaluar una SVR.
// El valor numérico c_i del modelo se obtiene con NumericValue().
type ComplianceStatus int

const (
	StatusPendiente       ComplianceStatus = iota // No evaluada todavía
	StatusCumple                                  // c_i = 1.0
	StatusCumpleParcial                           // c_i = 0.5
	StatusNoCumple                                // c_i = 0.0
	StatusFaltaEvidencia                          // No verificable automáticamente, sin evidencia
	StatusManualRequerido                         // Requiere revisión manual (excluida del cálculo)
	StatusNoAplica                                // No aplica al entorno (excluida del cálculo)
)

func (c ComplianceStatus) String() string {
	switch c {
	case StatusCumple:
		return "Cumple"
	case StatusCumpleParcial:
		return "Cumple parcialmente"
	case StatusNoCumple:
		return "No cumple"
	case StatusFaltaEvidencia:
		return "Falta evidencia"
	case StatusManualRequerido:
		return "Pendiente revisión manual"
	case StatusNoAplica:
		return "No aplica"
	default:
		return "Pendiente"
	}
}

// NumericValue retorna el valor c_i del modelo. Los estados que no son
// cumple/parcial/no-cumple no aportan al cálculo del score y deben ser
// excluidos antes por el módulo de scoring.
func (c ComplianceStatus) NumericValue() float64 {
	switch c {
	case StatusCumple:
		return 1.0
	case StatusCumpleParcial:
		return 0.5
	case StatusNoCumple:
		return 0.0
	default:
		return 0.0
	}
}

// CountsForScore indica si el estado contribuye al cálculo del Security Score.
// Reglas pendientes, manuales o sin evidencia se reportan pero no participan.
func (c ComplianceStatus) CountsForScore() bool {
	return c == StatusCumple || c == StatusCumpleParcial || c == StatusNoCumple
}

// ValidationMode indica cómo se evalúa una SVR.
type ValidationMode int

const (
	ModeAutomatic     ValidationMode = iota // Verificable totalmente por el programa
	ModeSemiAutomatic                       // Evidencia parcial + criterio humano
	ModeManual                              // Requiere revisión humana / acceso admin
)

func (m ValidationMode) String() string {
	switch m {
	case ModeAutomatic:
		return "Automática"
	case ModeSemiAutomatic:
		return "Semi-automática"
	case ModeManual:
		return "Manual"
	default:
		return "Desconocida"
	}
}

// Domain identifica los cuatro dominios definidos en el modelo.
type Domain string

const (
	DomainNet Domain = "Red y aislamiento"
	DomainHar Domain = "Hardening de host y plataforma"
	DomainIam Domain = "Identidades, acceso y secretos"
	DomainMon Domain = "Monitoreo, integridad y trazabilidad"
)

// AllDomains retorna los dominios en el orden canónico de presentación.
func AllDomains() []Domain {
	return []Domain{DomainNet, DomainHar, DomainIam, DomainMon}
}

// SVR (Security Verification Rule) es la unidad básica de evaluación.
type SVR struct {
	ID        string
	Domain    Domain
	Criterion string
	Evidence  string
	Method    string
	Severity  Severity
	Reference string
	Mode      ValidationMode
	Critical  bool // Si true, su incumplimiento bloquea la promoción del entorno.
}

// RuleResult es el resultado de evaluar una SVR sobre el contexto actual.
type RuleResult struct {
	Rule     SVR              `json:"rule"`
	Status   ComplianceStatus `json:"status"`
	Evidence string           `json:"evidence"` // Evidencia concreta recopilada
	Notes    string           `json:"notes"`    // Notas para el evaluador
	// Manual queda no-nil cuando un evaluador completó una verificación
	// manual o sobreescribió un resultado automático mediante un archivo de
	// revisión (--review). El módulo de scoring no necesita conocer este
	// campo: para cuando se ejecuta, Status ya refleja el veredicto humano.
	Manual *ManualVerdict `json:"manual,omitempty"`
}

// ManualVerdict registra la decisión humana sobre una SVR. Se conserva en el
// snapshot para que la trazabilidad siga viva entre corridas (SVR-MON-03).
type ManualVerdict struct {
	Reviewer   string    `json:"reviewer,omitempty"`
	ReviewedAt time.Time `json:"reviewed_at,omitempty"`
	Evidence   string    `json:"evidence,omitempty"`
	Notes      string    `json:"notes,omitempty"`
}

// EvalContext acumula toda la información que los módulos van produciendo
// durante una corrida. Se construye en el módulo de Entrada y se completa
// en Descubrimiento, antes de pasar al de Validación.
type EvalContext struct {
	// Identificación del entorno
	EnvironmentName string
	EnvironmentType string // p.ej. "staging"
	StackType       string // "web", "api", "container", etc.
	Timestamp       time.Time

	// Entrada del usuario
	Target          string   // dominio principal
	IPAddress       string   // IP del servidor
	ExpectedPorts   []int    // puertos esperados según el responsable del entorno
	RepoPath        string   // ruta local opcional al repositorio
	ProductionRefs  []string // IPs/hosts de producción para validar aislamiento
	AdminInterfaces []string // rutas/puertos administrativos esperados

	// LocalHostScan activa verificaciones invasivas sobre el host LOCAL donde
	// se ejecuta el cliente. Cuando es true (vía --local-host-scan o
	// local_host_scan: true en YAML), el módulo de descubrimiento ejecuta
	// comandos como `dpkg --list`, `systemctl list-units`, `ss -tlnp`,
	// `ufw status`, `journalctl`, lee /etc/ssh/sshd_config y permisos de
	// archivos sensibles, todo SOBRE EL EQUIPO DEL EVALUADOR (nunca sobre
	// hosts remotos). Habilita la verificación automática de varias reglas
	// de hardening que de otro modo quedan en "manual".
	//
	// El usuario debe activarla explícitamente porque:
	//   1. Lee información sensible del sistema (lista de paquetes, usuarios,
	//      configuración de SSH) que no es necesaria en un scan estándar.
	//   2. Solo tiene sentido cuando el equipo donde corre el cliente ES el
	//      host de staging (típico en CI/CD o evaluación local del servidor).
	//      Si se corre desde una laptop apuntando a un staging remoto, los
	//      resultados describen la laptop, no el servidor.
	LocalHostScan bool

	// SSHTarget activa el modo remoto: el cliente abre una sesión SSH al
	// host indicado (user@host) y ejecuta sobre él los mismos chequeos del
	// modo invasivo. SSHTarget vacío significa modo desactivado.
	// Pensado primariamente para CI/CD: las credenciales (llave privada)
	// se pasan vía secret del CI y nunca se persisten.
	SSHTarget  string
	SSHPort    int    // 0 -> 22 default
	SSHKeyPath string // ruta a llave privada; vacío usa agente ssh-agent o ~/.ssh
	SSHUseSudo bool   // prefijar con `sudo -n` los comandos privilegiados

	// Serverless declara que el entorno corre sobre arquitectura FaaS o
	// managed (Vercel, Netlify, AWS Lambda + API Gateway, Cloudflare
	// Workers, Cloud Run, Azure Functions, etc.). Cuando es true, el
	// cliente marca automáticamente como "No aplica" un conjunto fijo de
	// reglas de hardening de host cuya gestión es responsabilidad del
	// proveedor (parches, firewall local, permisos del filesystem,
	// auditd, logs en /var/log).
	//
	// La lista de reglas afectadas vive en internal/rules/not_applicable.go
	// y es intencionalmente cerrada (hardcoded): la decisión sobre qué se
	// considera "imposible de evaluar en serverless" pertenece al modelo,
	// no a la configuración del usuario. Esto evita que un evaluador
	// poco riguroso desactive reglas que sí debería evaluar usando este
	// flag como pretexto.
	//
	// Las reglas NA por serverless se renderizan en el HTML SIN controles
	// de veredicto: no se pueden sobreescribir desde la UI. Si el usuario
	// considera que la regla sí aplica a su caso particular, debe poner
	// serverless=false y aceptar el resto del modelo.
	Serverless bool

	// Resultados de descubrimiento
	Discovery DiscoveryData

	// Resultados de validación
	Results []RuleResult
}

// DiscoveryData almacena la evidencia técnica recopilada por el módulo
// de Descubrimiento. Es lo que el módulo de Validación contrasta contra cada SVR.
type DiscoveryData struct {
	DNSResolved         []string
	DNSError            string
	OpenPorts           []PortFinding
	UnexpectedPorts     []int
	MissingPorts        []int
	TLS                 TLSFinding
	HTTPHeaders         map[string]string
	HTTPStatus          int
	HTTPError           string
	Banners             map[int]string // puerto -> banner detectado
	SecretFindings      []SecretFinding
	ProductionReachable []string // hosts de prod alcanzables (mala señal)
	AdminExposed        []AdminFinding
	LegacyServices      []int // puertos heredados encontrados

	// Contexto de git: necesario para distinguir secretos realmente
	// expuestos (en archivos trackeados o en el historial) de los que solo
	// existen en el equipo de desarrollo y no se han propagado.
	Git GitContext `json:"git"`

	// Hallazgos específicos sobre archivos .env / variables de entorno.
	// Se separan del listado general de secretos porque el criterio de
	// SVR-IAM-07 depende del estado de tracking de cada archivo y no del
	// contenido por sí solo.
	EnvFiles []EnvFileFinding `json:"env_files"`

	// LocalHost contiene los resultados de las verificaciones invasivas
	// sobre el host LOCAL del evaluador. Solo se rellena cuando el usuario
	// activó --local-host-scan. Si está vacío, todos los validadores que
	// dependen de él caen al comportamiento previo (manual/falta-evidencia).
	LocalHost LocalHostData `json:"local_host"`
}

// LocalHostData agrupa la evidencia recopilada por las verificaciones del
// modo invasivo. Todos los campos son opt-in: si LocalHostScan=false en el
// contexto, esta struct queda en cero y los validadores se comportan como
// antes (devuelven StatusManualRequerido o StatusFaltaEvidencia).
type LocalHostData struct {
	// Available indica si se ejecutaron las verificaciones. Cuando es false
	// los validadores deben asumir que el modo no se activó y no fallar
	// silenciosamente.
	Available bool `json:"available"`

	// Mode indica cómo se obtuvo la evidencia: "local-host" (el cliente
	// corre EN el host inspeccionado) o "ssh" (el cliente abrió una sesión
	// SSH contra un host remoto). El reporte HTML lo usa para mostrar
	// claramente qué tan reciente es la evidencia y de qué máquina vino.
	Mode      string `json:"mode,omitempty"`
	HostLabel string `json:"host_label,omitempty"` // p.ej. "este equipo (linux)" o "deploy@10.0.0.5"

	// OS describe el sistema operativo donde corre el cliente.
	OS        string   `json:"os,omitempty"`         // linux, darwin, windows
	OSVersion string   `json:"os_version,omitempty"` // e.g. "Ubuntu 22.04.4 LTS"
	Kernel    string   `json:"kernel,omitempty"`     // uname -r
	Errors    []string `json:"errors,omitempty"`     // mensajes de las comprobaciones que no pudieron ejecutarse

	// HAR-04: estado de parches.
	// PackagesOutdated cuenta los paquetes con actualización disponible.
	// SecurityUpdatesPending cuenta los marcados como actualización de
	// seguridad por el gestor de paquetes (apt) cuando es discernible.
	PackagesOutdated       int    `json:"packages_outdated,omitempty"`
	SecurityUpdatesPending int    `json:"security_updates_pending,omitempty"`
	PackagesCheckedAt      string `json:"packages_checked_at,omitempty"` // edad del cache de apt
	PackagesError          string `json:"packages_error,omitempty"`

	// HAR-05: firewall local.
	FirewallActive      bool   `json:"firewall_active"`
	FirewallTool        string `json:"firewall_tool,omitempty"` // ufw, firewalld, iptables, nftables, none
	FirewallRulesCount  int    `json:"firewall_rules_count,omitempty"`
	FirewallDefaultDeny bool   `json:"firewall_default_deny,omitempty"`

	// HAR-08: permisos en archivos sensibles.
	// Cada entrada describe un path inseguro encontrado (permisos
	// mundo-legibles sobre archivos que no deberían serlo).
	SensitiveFiles []SensitiveFileFinding `json:"sensitive_files,omitempty"`

	// HAR-10 / MON-01: configuración de auditoría y logs.
	AuditdActive bool     `json:"auditd_active"`
	AuditError   string   `json:"audit_error,omitempty"`
	LogsPresent  []string `json:"logs_present,omitempty"`  // archivos de log con tamaño > 0 en /var/log
	LogsRotating bool     `json:"logs_rotating,omitempty"` // existe logrotate.conf con reglas activas

	// SSH: complemento de SVR-HAR-03 cuando el host es local.
	SSHConfigPath   string `json:"ssh_config_path,omitempty"`
	SSHPermitRoot   string `json:"ssh_permit_root,omitempty"`   // valor crudo: "yes", "no", "prohibit-password", "without-password" o ""
	SSHPasswordAuth string `json:"ssh_password_auth,omitempty"` // "yes" / "no"
	SSHPubkeyAuth   string `json:"ssh_pubkey_auth,omitempty"`
}

// SensitiveFileFinding describe un archivo sensible con permisos laxos.
type SensitiveFileFinding struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"` // p.ej. "0644", "0777"
	Owner   string `json:"owner,omitempty"`
	Problem string `json:"problem"` // descripción legible: "lectura mundo permitida en clave privada"
}

// GitContext describe el estado del repositorio frente a git. Cuando el
// repositorio no es un repo git, o git no está disponible en el PATH, el
// campo Available queda en false y los validadores caen al comportamiento
// previo (basado solo en presencia de archivos en disco).
type GitContext struct {
	Available     bool     `json:"available"`
	Error         string   `json:"error,omitempty"`
	TrackedFiles  []string `json:"tracked_files,omitempty"` // rutas relativas trackeadas hoy
	HistoryFiles  []string `json:"history_files,omitempty"` // archivos que alguna vez existieron en el historial
	GitignoreSeen bool     `json:"gitignore_seen"`
}

// EnvFileFinding describe el estado de un archivo .env (o equivalente)
// detectado en el repositorio. Es la base para evaluar SVR-IAM-07 con
// criterio justo: un .env solo local y gitignored no es exposición de
// secretos, mientras que uno trackeado o en historial sí lo es.
type EnvFileFinding struct {
	Path       string `json:"path"`
	Tracked    bool   `json:"tracked"`
	InHistory  bool   `json:"in_history"`
	Gitignored bool   `json:"gitignored"`
	HasSecrets bool   `json:"has_secrets"`
}

// PortFinding describe un puerto abierto detectado.
type PortFinding struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// TLSFinding es el resultado del análisis del canal TLS.
type TLSFinding struct {
	Tested      bool      `json:"tested"`
	Available   bool      `json:"available"`
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite"`
	CertSubject string    `json:"cert_subject"`
	CertIssuer  string    `json:"cert_issuer"`
	NotAfter    time.Time `json:"not_after"`
	IsExpired   bool      `json:"is_expired"`
	IsTLS13     bool      `json:"is_tls13"`
	Error       string    `json:"error,omitempty"`
}

// SecretFinding describe un secreto presuntamente expuesto en el repositorio.
type SecretFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Pattern  string `json:"pattern"`
	Match    string `json:"match"` // recortado/redactado
	Severity string `json:"severity"`
	// Tracked indica si el archivo está actualmente trackeado por git.
	// InHistory indica si el archivo aparece en el historial aunque hoy no
	// esté trackeado (un .env removido pero histórico sigue siendo riesgo).
	// Si el repositorio no es un repo git, ambos quedan en false y los
	// validadores deben usar la heurística previa (presencia en disco).
	Tracked   bool `json:"tracked"`
	InHistory bool `json:"in_history"`
	// IsFixture marca hallazgos en archivos de test, ejemplos o fixtures.
	// Estos NO penalizan SVR-IAM-04 porque corresponden a cadenas de prueba
	// (e.g. "Bearer invalid-token-for-test"), no a secretos reales filtrados.
	// Se reportan en una sección aparte del HTML para transparencia.
	IsFixture bool `json:"is_fixture,omitempty"`
}

// AdminFinding describe un punto administrativo expuesto.
type AdminFinding struct {
	Port        int    `json:"port"`
	Description string `json:"description"`
	// Resultado del probe HTTP/HTTPS opcional sobre la interface admin.
	// Probed=true si pudimos hacer una petición; HTTPStatus es el código
	// de respuesta. AuthChallenge=true si la respuesta fue 401/403/407 o
	// trajo header WWW-Authenticate, lo que indica que el endpoint pide
	// credenciales antes de servir contenido.
	// Estos campos los usa SVR-IAM-08 para dictaminar automáticamente si
	// el acceso externo a recursos internos está asociado a identidades.
	Probed        bool   `json:"probed,omitempty"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	AuthChallenge bool   `json:"auth_challenge,omitempty"`
	ProbeError    string `json:"probe_error,omitempty"`
}
