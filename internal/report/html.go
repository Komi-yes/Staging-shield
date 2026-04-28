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
	Env             *ctx.EvalContext
	Stats           scoring.Stats
	GeneratedAt     string
	DomainList      []domainView
	CriticalView    []ruleView
	FailedView      []ruleView
	NoEvidenceView  []ruleView
	ManualView      []ruleView
	PassedView      []ruleView
	Recommendations []string
	OpenPortsList   []string
	SecretsCount    int
	HighSecrets     int
	Discovery       discoveryView
}

type domainView struct {
	Name      string
	Score     float64
	ScoreStr  string
	BarPct    float64
	BadgeCls  string
	Cumple    int
	Parcial   int
	NoCumple  int
	NoEval    int
	Total     int
}

type ruleView struct {
	ID        string
	Domain    string
	Criterion string
	Severity  string
	SevClass  string
	Reference string
	Mode      string
	Status    string
	StatusCls string
	Evidence  string
	Notes     string
	Critical  bool
}

type discoveryView struct {
	HasDNS       bool
	DNSResolved  []string
	DNSError     string
	OpenPorts    []ctx.PortFinding
	UnexpectedPorts []int
	MissingPorts []int
	TLS          ctx.TLSFinding
	HTTPHeaders  []headerView
	HTTPStatus   int
	AdminExposed []ctx.AdminFinding
	Legacy       []int
	ProductionReachable []string
	Secrets      []ctx.SecretFinding
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

	// Reglas - tres listas separadas
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
	}

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
		Reference: r.Rule.Reference,
		Mode:      r.Rule.Mode.String(),
		Status:    r.Status.String(),
		StatusCls: statusClass(r.Status),
		Evidence:  r.Evidence,
		Notes:     r.Notes,
		Critical:  r.Rule.Critical,
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
