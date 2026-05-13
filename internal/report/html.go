// HTML report generator. Embed la plantilla con //go:embed para que el
// binario sea autocontenido.
package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	ctx "github.com/stagingshield/staging-shield/internal/context"
	"github.com/stagingshield/staging-shield/internal/scoring"
)

//go:embed report.html.tmpl
var htmlTemplate string

// htmlData es lo que se le pasa a la plantilla.
type htmlData struct {
	Env                 *ctx.EvalContext
	Stats               scoring.Stats
	GeneratedAt         string
	DomainList          []domainView
	CriticalView        []ruleView
	FailedView          []ruleView
	NoEvidenceView      []ruleView
	ManualView          []ruleView
	PassedView          []ruleView
	NotApplicableView   []ruleView          // Reglas declaradas no-aplicables (serverless u override)
	PassedByDomain      []passedDomainBlock // PassedView agrupado por dominio para mostrar evidencia con transparencia
	Recommendations     []string
	OpenPortsList       []string
	SecretsCount        int
	RealSecretsCount    int
	FixtureSecretsCount int
	HighSecrets         int
	TrackedSecrets      int // secretos en archivos trackeados o en historial
	ManualSlotsTotal    int // total de SVR únicas que el usuario puede revisar manualmente
	Discovery           discoveryView
}

// passedDomainBlock agrupa SVR cumplidas (cumple + parcial) por dominio para
// que la sección de transparencia "SVR que cumplen y su evidencia" pueda
// renderizarlas con un encabezado por dominio en lugar de en una sola lista
// plana de 20+ tarjetas.
type passedDomainBlock struct {
	Name  string
	Rules []ruleView
}

type domainView struct {
	Name     string
	Score    float64
	ScoreStr string
	BarPct   float64
	BadgeCls string
	Cumple   int
	Parcial  int
	NoCumple int
	NoEval   int
	Total    int
}

type ruleView struct {
	ID        string
	Domain    string
	Criterion string
	Severity  string
	SevClass  string
	SevWeight int // peso numérico (1, 2, 3) para el JS
	Reference string
	Mode      string
	Status    string
	StatusCls string
	StatusKey string // "cumple" | "parcial" | "nocumple" | "manual" | "missing" | "pending" — clave canónica para el JS
	Evidence  string
	Notes     string
	Critical  bool
	CanReview bool // true si el usuario puede emitir veredicto manual sobre esta regla desde el HTML
}

type discoveryView struct {
	HasDNS              bool
	DNSResolved         []string
	DNSError            string
	OpenPorts           []ctx.PortFinding
	UnexpectedPorts     []int
	MissingPorts        []int
	TLS                 ctx.TLSFinding
	HTTPHeaders         []headerView
	HTTPStatus          int
	AdminExposed        []ctx.AdminFinding
	Legacy              []int
	ProductionReachable []string
	Secrets             []ctx.SecretFinding
	Git                 ctx.GitContext
	EnvFiles            []ctx.EnvFileFinding
	EnvValueLeaks       []ctx.EnvValueLeakFinding
	LocalHost           ctx.LocalHostData
}

type headerView struct {
	Name  string
	Value string
}

// WriteHTML genera el reporte HTML en path. Crea directorios padre si faltan.
func WriteHTML(path string, ec *ctx.EvalContext, stats scoring.Stats) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data := buildHTMLData(ec, stats)

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"join":   strings.Join,
		"intCSV": intCSV,
		// 'js' escapa cadenas para que sean seguras al inyectarlas en
		// posiciones JS (con comillas dobles). html/template ya escapa
		// HTML por defecto, pero para los literales JSON inline en el
		// bloque <script> necesitamos escape JS específico.
		"js": jsString,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parseando plantilla: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

// jsString convierte una cadena en un literal JS seguro entre comillas dobles.
// Reemplaza caracteres de control y comillas para evitar XSS y errores de parseo.
func jsString(s string) string {
	out := strings.Builder{}
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			out.WriteString(`\\`)
		case '"':
			out.WriteString(`\"`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '<':
			out.WriteString(`\u003c`)
		case '>':
			out.WriteString(`\u003e`)
		case '&':
			out.WriteString(`\u0026`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func buildHTMLData(ec *ctx.EvalContext, stats scoring.Stats) htmlData {
	data := htmlData{
		Env:         ec,
		Stats:       stats,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	// Dominios
	for _, d := range ctx.AllDomains() {
		dc := stats.DomainCounts[d]
		data.DomainList = append(data.DomainList, domainView{
			Name:     string(d),
			Score:    dc.Score,
			ScoreStr: fmt.Sprintf("%.2f", dc.Score),
			BarPct:   dc.Score,
			BadgeCls: scoreBadgeClass(dc.Score),
			Cumple:   dc.Cumple,
			Parcial:  dc.Parcial,
			NoCumple: dc.NoCumple,
			NoEval:   dc.NoEvaluado,
			Total:    dc.Total,
		})
	}

	// Reglas - cuatro listas separadas + NotApplicableView para las
	// declaradas no-aplicables (serverless + override del usuario).
	for _, r := range ec.Results {
		rv := toRuleView(r)
		switch r.Status {
		case ctx.StatusNoCumple:
			if r.Rule.Critical {
				data.CriticalView = append(data.CriticalView, rv)
			}
			data.FailedView = append(data.FailedView, rv)
		case ctx.StatusFaltaEvidencia:
			data.NoEvidenceView = append(data.NoEvidenceView, rv)
		case ctx.StatusManualRequerido:
			data.ManualView = append(data.ManualView, rv)
		case ctx.StatusCumple, ctx.StatusCumpleParcial:
			data.PassedView = append(data.PassedView, rv)
		case ctx.StatusNoAplica:
			data.NotApplicableView = append(data.NotApplicableView, rv)
		}
	}

	// Ordenar reglas fallidas por severidad
	sort.SliceStable(data.FailedView, func(i, j int) bool {
		// SevClass 'high' antes que 'med' antes que 'low'
		order := map[string]int{"high": 0, "med": 1, "low": 2}
		oi, oj := order[data.FailedView[i].SevClass], order[data.FailedView[j].SevClass]
		if oi != oj {
			return oi < oj
		}
		return data.FailedView[i].ID < data.FailedView[j].ID
	})
	sort.SliceStable(data.PassedView, func(i, j int) bool {
		return data.PassedView[i].ID < data.PassedView[j].ID
	})
	sort.SliceStable(data.NoEvidenceView, func(i, j int) bool {
		return data.NoEvidenceView[i].ID < data.NoEvidenceView[j].ID
	})
	sort.SliceStable(data.ManualView, func(i, j int) bool {
		if data.ManualView[i].Domain != data.ManualView[j].Domain {
			return data.ManualView[i].Domain < data.ManualView[j].Domain
		}
		return data.ManualView[i].ID < data.ManualView[j].ID
	})
	sort.SliceStable(data.CriticalView, func(i, j int) bool {
		return data.CriticalView[i].ID < data.CriticalView[j].ID
	})

	// Agrupar PassedView por dominio respetando el orden canónico de dominios.
	// Cada bloque queda con sus reglas ordenadas por ID para que la lectura sea
	// estable entre corridas (SVR-MON-05). Los dominios sin reglas cumplidas se
	// omiten para no producir bloques vacíos visualmente ruidosos.
	{
		byDom := make(map[ctx.Domain][]ruleView)
		for _, rv := range data.PassedView {
			d := ctx.Domain(rv.Domain)
			byDom[d] = append(byDom[d], rv)
		}
		for _, d := range ctx.AllDomains() {
			if rs, ok := byDom[d]; ok && len(rs) > 0 {
				sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
				data.PassedByDomain = append(data.PassedByDomain, passedDomainBlock{
					Name:  string(d),
					Rules: rs,
				})
			}
		}
	}

	// Recomendaciones
	data.Recommendations = buildRecommendations(stats)

	// Discovery view
	data.Discovery = discoveryView{
		HasDNS:              ec.Discovery.DNSError == "" && len(ec.Discovery.DNSResolved) > 0,
		DNSResolved:         ec.Discovery.DNSResolved,
		DNSError:            ec.Discovery.DNSError,
		OpenPorts:           ec.Discovery.OpenPorts,
		UnexpectedPorts:     ec.Discovery.UnexpectedPorts,
		MissingPorts:        ec.Discovery.MissingPorts,
		TLS:                 ec.Discovery.TLS,
		HTTPStatus:          ec.Discovery.HTTPStatus,
		AdminExposed:        ec.Discovery.AdminExposed,
		Legacy:              ec.Discovery.LegacyServices,
		ProductionReachable: ec.Discovery.ProductionReachable,
		Secrets:             ec.Discovery.SecretFindings,
		Git:                 ec.Discovery.Git,
		EnvFiles:            ec.Discovery.EnvFiles,
		EnvValueLeaks:       ec.Discovery.EnvValueLeaks,
		LocalHost:           ec.Discovery.LocalHost,
	}
	for k, v := range ec.Discovery.HTTPHeaders {
		data.Discovery.HTTPHeaders = append(data.Discovery.HTTPHeaders, headerView{Name: k, Value: v})
	}
	sort.Slice(data.Discovery.HTTPHeaders, func(i, j int) bool {
		return data.Discovery.HTTPHeaders[i].Name < data.Discovery.HTTPHeaders[j].Name
	})

	data.SecretsCount = len(ec.Discovery.SecretFindings)
	for _, s := range ec.Discovery.SecretFindings {
		if s.Severity == "alto" {
			data.HighSecrets++
		}
		if s.Tracked || s.InHistory {
			data.TrackedSecrets++
		}
		if s.IsFixture {
			data.FixtureSecretsCount++
		} else {
			data.RealSecretsCount++
		}
	}

	// Total de SVR únicas que pueden recibir veredicto manual desde el HTML.
	// Equivale a |ManualView ∪ NoEvidenceView|, pero sin contar duplicados.
	manualSlotIDs := make(map[string]struct{})
	for _, r := range ec.Results {
		if r.Status == ctx.StatusManualRequerido || r.Status == ctx.StatusFaltaEvidencia {
			manualSlotIDs[r.Rule.ID] = struct{}{}
		}
	}
	data.ManualSlotsTotal = len(manualSlotIDs)

	// Lista cómoda de puertos abiertos como strings
	for _, f := range ec.Discovery.OpenPorts {
		if f.Banner != "" {
			data.OpenPortsList = append(data.OpenPortsList, fmt.Sprintf("%d (%s)", f.Port, f.Banner))
		} else {
			data.OpenPortsList = append(data.OpenPortsList, fmt.Sprintf("%d", f.Port))
		}
	}

	return data
}

func toRuleView(r ctx.RuleResult) ruleView {
	return ruleView{
		ID:        r.Rule.ID,
		Domain:    string(r.Rule.Domain),
		Criterion: r.Rule.Criterion,
		Severity:  r.Rule.Severity.String(),
		SevClass:  severityClass(r.Rule.Severity),
		SevWeight: int(r.Rule.Severity), // 1, 2, 3
		Reference: r.Rule.Reference,
		Mode:      r.Rule.Mode.String(),
		Status:    r.Status.String(),
		StatusCls: statusClass(r.Status),
		StatusKey: statusKey(r.Status),
		Evidence:  r.Evidence,
		Notes:     r.Notes,
		Critical:  r.Rule.Critical,
		// Solo permitimos revisión manual desde la UI sobre reglas que el
		// motor automático no resolvió definitivamente. Las que ya están
		// en cumple/parcial/no-cumple no se pueden sobreescribir.
		// Las marcadas como NoAplica por serverless tampoco se pueden
		// sobreescribir desde la UI (decisión del modelo, no del evaluador):
		// el caller (buildHTMLData) ajusta CanReview a false en ese caso.
		CanReview: r.Status == ctx.StatusManualRequerido || r.Status == ctx.StatusFaltaEvidencia,
	}
}

// statusKey devuelve la clave canónica del estado, usada por el JS para
// determinar el peso c_i de la regla durante el recálculo en vivo.
func statusKey(s ctx.ComplianceStatus) string {
	switch s {
	case ctx.StatusCumple:
		return "cumple"
	case ctx.StatusCumpleParcial:
		return "parcial"
	case ctx.StatusNoCumple:
		return "nocumple"
	case ctx.StatusFaltaEvidencia:
		return "missing"
	case ctx.StatusManualRequerido:
		return "manual"
	case ctx.StatusNoAplica:
		return "naplica"
	default:
		return "pending"
	}
}

func severityClass(s ctx.Severity) string {
	switch s {
	case ctx.SevAlta:
		return "high"
	case ctx.SevMedia:
		return "med"
	default:
		return "low"
	}
}

func statusClass(s ctx.ComplianceStatus) string {
	switch s {
	case ctx.StatusCumple:
		return "pass"
	case ctx.StatusCumpleParcial:
		return "partial"
	case ctx.StatusNoCumple:
		return "fail"
	case ctx.StatusFaltaEvidencia:
		return "missing"
	case ctx.StatusManualRequerido:
		return "manual"
	case ctx.StatusNoAplica:
		return "naplica"
	default:
		return "pending"
	}
}

func scoreBadgeClass(s float64) string {
	switch {
	case s >= 80:
		return "score-good"
	case s >= 60:
		return "score-warn"
	default:
		return "score-bad"
	}
}

func intCSV(xs []int) string {
	if len(xs) == 0 {
		return "(ninguno)"
	}
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, ", ")
}
