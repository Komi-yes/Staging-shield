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
	StatusPendiente        ComplianceStatus = iota // No evaluada todavía
	StatusCumple                                   // c_i = 1.0
	StatusCumpleParcial                            // c_i = 0.5
	StatusNoCumple                                 // c_i = 0.0
	StatusFaltaEvidencia                           // No verificable automáticamente, sin evidencia
	StatusManualRequerido                          // Requiere revisión manual (excluida del cálculo)
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
	ID         string
	Domain     Domain
	Criterion  string
	Evidence   string
	Method     string
	Severity   Severity
	Reference  string
	Mode       ValidationMode
	Critical   bool // Si true, su incumplimiento bloquea la promoción del entorno.
}

// RuleResult es el resultado de evaluar una SVR sobre el contexto actual.
type RuleResult struct {
	Rule     SVR              `json:"rule"`
	Status   ComplianceStatus `json:"status"`
	Evidence string           `json:"evidence"` // Evidencia concreta recopilada
	Notes    string           `json:"notes"`    // Notas para el evaluador
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

	// Resultados de descubrimiento
	Discovery DiscoveryData

	// Resultados de validación
	Results []RuleResult
}

// DiscoveryData almacena la evidencia técnica recopilada por el módulo
// de Descubrimiento. Es lo que el módulo de Validación contrasta contra cada SVR.
type DiscoveryData struct {
	DNSResolved   []string
	DNSError      string
	OpenPorts     []PortFinding
	UnexpectedPorts []int
	MissingPorts  []int
	TLS           TLSFinding
	HTTPHeaders   map[string]string
	HTTPStatus    int
	HTTPError     string
	Banners       map[int]string // puerto -> banner detectado
	SecretFindings []SecretFinding
	ProductionReachable []string // hosts de prod alcanzables (mala señal)
	AdminExposed  []AdminFinding
	LegacyServices []int // puertos heredados encontrados
}

// PortFinding describe un puerto abierto detectado.
type PortFinding struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// TLSFinding es el resultado del análisis del canal TLS.
type TLSFinding struct {
	Tested        bool      `json:"tested"`
	Available     bool      `json:"available"`
	Version       string    `json:"version"`
	CipherSuite   string    `json:"cipher_suite"`
	CertSubject   string    `json:"cert_subject"`
	CertIssuer    string    `json:"cert_issuer"`
	NotAfter      time.Time `json:"not_after"`
	IsExpired     bool      `json:"is_expired"`
	IsTLS13       bool      `json:"is_tls13"`
	Error         string    `json:"error,omitempty"`
}

// SecretFinding describe un secreto presuntamente expuesto en el repositorio.
type SecretFinding struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Pattern   string `json:"pattern"`
	Match     string `json:"match"` // recortado/redactado
	Severity  string `json:"severity"`
}

// AdminFinding describe un punto administrativo expuesto.
type AdminFinding struct {
	Port        int    `json:"port"`
	Description string `json:"description"`
}
