// Package scoring implementa el Módulo 4 (Scoring) del programa cliente.
// Aplica la fórmula del Security Score definida en el modelo:
//
//   Score = 100 × Σ(c_i × w_i × d_i) ÷ Σ(w_i × d_i)
//
// Score por dominio:
//
//   Score(d) = 100 × Σ(c_i × w_i) ÷ Σ(w_i)
//
// Y la condición de aptitud:
//
//   Apto = 1 si no hay ninguna SVR crítica en estado 'no cumple'.
//
// Solo las reglas con StatusCumple, StatusCumpleParcial o StatusNoCumple
// participan del cálculo. Las reglas manuales o sin evidencia se reportan
// pero no contaminan el score.
package scoring

import (
	"sort"

	ctx "github.com/stagingshield/staging-shield/internal/context"
)

// DomainWeight permite ponderar dominios entre sí. Por defecto todos los
// dominios pesan igual (1.0). El parámetro existe para futuras calibraciones
// empíricas, conforme a la sección "Limitaciones del Modelo" del documento.
type DomainWeight map[ctx.Domain]float64

// DefaultDomainWeights asigna peso 1.0 a cada dominio.
func DefaultDomainWeights() DomainWeight {
	return DomainWeight{
		ctx.DomainNet: 1.0,
		ctx.DomainHar: 1.0,
		ctx.DomainIam: 1.0,
		ctx.DomainMon: 1.0,
	}
}

// Stats agrupa el resultado completo del scoring sobre una corrida.
type Stats struct {
	GlobalScore       float64
	DomainScores      map[ctx.Domain]float64
	DomainCounts      map[ctx.Domain]DomainCount
	TotalRules        int
	StatusCounts      map[ctx.ComplianceStatus]int
	CriticalFailures  []ctx.RuleResult // SVR críticas en estado no cumple
	NotEvaluated      []ctx.RuleResult // Manuales + falta de evidencia
	Failed            []ctx.RuleResult // No cumple, ordenadas por severidad desc
	Apto              bool
	AutoCoverage      float64 // % reglas evaluadas automáticamente vs total
	SeverityBreakdown map[ctx.Severity]int // distribución de severidades en NoCumple
}

// DomainCount contabiliza por dominio cuántas reglas hay en cada estado.
type DomainCount struct {
	Total      int
	Cumple     int
	Parcial    int
	NoCumple   int
	NoEvaluado int
	Score      float64
}

// Compute aplica el modelo de scoring a los resultados acumulados en ec.Results.
// Devuelve un Stats listo para ser consumido por el módulo de Reporte.
func Compute(ec *ctx.EvalContext, weights DomainWeight) Stats {
	if weights == nil {
		weights = DefaultDomainWeights()
	}

	stats := Stats{
		DomainScores:      make(map[ctx.Domain]float64),
		DomainCounts:      make(map[ctx.Domain]DomainCount),
		StatusCounts:      make(map[ctx.ComplianceStatus]int),
		SeverityBreakdown: make(map[ctx.Severity]int),
		Apto:              true,
	}

	// Inicializar dominios para que aparezcan aunque no tengan reglas evaluadas
	for _, d := range ctx.AllDomains() {
		stats.DomainCounts[d] = DomainCount{}
	}

	// Acumuladores para fórmula global y por dominio
	globalNum := 0.0
	globalDen := 0.0
	domNum := make(map[ctx.Domain]float64)
	domDen := make(map[ctx.Domain]float64)
	for _, d := range ctx.AllDomains() {
		domNum[d] = 0
		domDen[d] = 0
	}

	autoEvaluated := 0

	for _, r := range ec.Results {
		stats.TotalRules++
		stats.StatusCounts[r.Status]++

		dc := stats.DomainCounts[r.Rule.Domain]
		dc.Total++

		switch r.Status {
		case ctx.StatusCumple:
			dc.Cumple++
			autoEvaluated++
		case ctx.StatusCumpleParcial:
			dc.Parcial++
			autoEvaluated++
		case ctx.StatusNoCumple:
			dc.NoCumple++
			autoEvaluated++
			stats.Failed = append(stats.Failed, r)
			stats.SeverityBreakdown[r.Rule.Severity]++
			if r.Rule.Critical {
				stats.CriticalFailures = append(stats.CriticalFailures, r)
				stats.Apto = false
			}
		default:
			dc.NoEvaluado++
			stats.NotEvaluated = append(stats.NotEvaluated, r)
		}

		stats.DomainCounts[r.Rule.Domain] = dc

		// Solo reglas que cuentan participan del cálculo
		if !r.Status.CountsForScore() {
			continue
		}

		c := r.Status.NumericValue()
		w := float64(r.Rule.Severity)
		d := weights[r.Rule.Domain]
		if d == 0 {
			d = 1.0
		}

		globalNum += c * w * d
		globalDen += w * d

		domNum[r.Rule.Domain] += c * w
		domDen[r.Rule.Domain] += w
	}

	// Score por dominio
	for _, dom := range ctx.AllDomains() {
		var s float64
		if domDen[dom] > 0 {
			s = 100.0 * domNum[dom] / domDen[dom]
		}
		stats.DomainScores[dom] = s
		dc := stats.DomainCounts[dom]
		dc.Score = s
		stats.DomainCounts[dom] = dc
	}

	// Score global
	if globalDen > 0 {
		stats.GlobalScore = 100.0 * globalNum / globalDen
	}

	// Cobertura automática
	if stats.TotalRules > 0 {
		stats.AutoCoverage = 100.0 * float64(autoEvaluated) / float64(stats.TotalRules)
	}

	// Ordenar fallas por severidad descendente, luego por ID
	sort.SliceStable(stats.Failed, func(i, j int) bool {
		if stats.Failed[i].Rule.Severity != stats.Failed[j].Rule.Severity {
			return stats.Failed[i].Rule.Severity > stats.Failed[j].Rule.Severity
		}
		return stats.Failed[i].Rule.ID < stats.Failed[j].Rule.ID
	})

	// Ordenar críticas por ID
	sort.SliceStable(stats.CriticalFailures, func(i, j int) bool {
		return stats.CriticalFailures[i].Rule.ID < stats.CriticalFailures[j].Rule.ID
	})

	return stats
}
