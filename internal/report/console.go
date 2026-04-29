// Package report implementa el Módulo 5 del programa cliente.
// Genera reportes en consola y HTML, y resúmenes priorizados de hallazgos.
package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	ctx "github.com/stagingshield/staging-shield/internal/context"
	"github.com/stagingshield/staging-shield/internal/scoring"
)

// ANSI codes para resaltar en terminal compatible.
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[90m"
)

// PrintConsole genera el reporte resumido en stdout.
func PrintConsole(ec *ctx.EvalContext, stats scoring.Stats, useColor bool) {
	w := os.Stdout
	c := func(code string) string {
		if useColor {
			return code
		}
		return ""
	}

	// Encabezado
	fmt.Fprintln(w, c(colorBold)+strings.Repeat("═", 78)+c(colorReset))
	fmt.Fprintf(w, "%sSTAGING SHIELD%s — Reporte de evaluación de seguridad\n", c(colorBold), c(colorReset))
	fmt.Fprintln(w, strings.Repeat("─", 78))
	fmt.Fprintf(w, " Entorno    : %s%s%s (%s)\n", c(colorBold), ec.EnvironmentName, c(colorReset), ec.StackType)
	fmt.Fprintf(w, " Objetivo   : %s\n", ec.Target)
	if ec.IPAddress != "" {
		fmt.Fprintf(w, " IP         : %s\n", ec.IPAddress)
	}
	fmt.Fprintf(w, " Timestamp  : %s\n", ec.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w, c(colorBold)+strings.Repeat("═", 78)+c(colorReset))

	// Aptitud
	fmt.Fprintln(w)
	if stats.Apto {
		fmt.Fprintf(w, " %s✓ APTO%s para promoción a producción\n", c(colorGreen)+c(colorBold), c(colorReset))
	} else {
		fmt.Fprintf(w, " %s✗ NO APTO%s para promoción (existe al menos una SVR crítica en estado 'no cumple')\n", c(colorRed)+c(colorBold), c(colorReset))
	}

	// Score global
	fmt.Fprintln(w)
	fmt.Fprintf(w, " %sSecurity Score Global%s: %s%.2f / 100%s\n",
		c(colorBold), c(colorReset), c(colorBold)+scoreColor(stats.GlobalScore, useColor), stats.GlobalScore, c(colorReset))
	fmt.Fprintf(w, " Cobertura total       : %.1f%% (%d / %d reglas con veredicto)\n",
		stats.Coverage, stats.EvaluatedRules, stats.TotalRules)
	if stats.ManuallyReviewed > 0 {
		fmt.Fprintf(w, "    └─ automática      : %.1f%%  ·  manual (--review): %.1f%%  (%d veredictos humanos)\n",
			stats.AutoCoverage, stats.ManualCoverage, stats.ManuallyReviewed)
	} else {
		fmt.Fprintf(w, "    └─ automática      : %.1f%%  ·  manual: 0%% (sin --review)\n", stats.AutoCoverage)
	}
	fmt.Fprintln(w)

	// Score por dominio
	fmt.Fprintln(w, c(colorBold)+" Score por dominio:"+c(colorReset))
	for _, dom := range ctx.AllDomains() {
		s := stats.DomainScores[dom]
		dc := stats.DomainCounts[dom]
		bar := scoreBar(s, 32, useColor)
		fmt.Fprintf(w, "   %-37s %s %s%6.2f%s  (✓%d  ◐%d  ✗%d  ?%d)\n",
			truncate(string(dom), 37),
			bar,
			c(colorBold)+scoreColor(s, useColor),
			s,
			c(colorReset),
			dc.Cumple, dc.Parcial, dc.NoCumple, dc.NoEvaluado,
		)
	}
	fmt.Fprintln(w)

	// SVR críticas que bloquean promoción
	if len(stats.CriticalFailures) > 0 {
		fmt.Fprintln(w, c(colorRed)+c(colorBold)+" ▼ SVR CRÍTICAS QUE BLOQUEAN LA PROMOCIÓN:"+c(colorReset))
		for _, r := range stats.CriticalFailures {
			fmt.Fprintf(w, "   %s[%s]%s %s\n", c(colorRed)+c(colorBold), r.Rule.ID, c(colorReset), r.Rule.Criterion)
			if r.Evidence != "" {
				fmt.Fprintf(w, "        Evidencia: %s\n", indent(r.Evidence, 19))
			}
		}
		fmt.Fprintln(w)
	}

	// Hallazgos no cumplen ordenados por severidad
	if len(stats.Failed) > 0 {
		fmt.Fprintln(w, c(colorBold)+" ▼ Hallazgos por severidad:"+c(colorReset))
		for _, r := range stats.Failed {
			sevColor := severityColor(r.Rule.Severity, useColor)
			fmt.Fprintf(w, "   %s[%s]%s %s\n",
				sevColor+c(colorBold), r.Rule.ID, c(colorReset)+sevColor,
				r.Rule.Criterion)
			fmt.Fprintf(w, "        Severidad: %s%s%s | Dominio: %s | Ref: %s\n",
				sevColor, r.Rule.Severity.String(), c(colorReset),
				r.Rule.Domain, r.Rule.Reference)
			if r.Evidence != "" {
				fmt.Fprintf(w, "        Evidencia: %s\n", indent(r.Evidence, 19))
			}
			if r.Notes != "" {
				fmt.Fprintf(w, "        %sNota:%s      %s\n", c(colorGray), c(colorReset), indent(r.Notes, 19))
			}
		}
		fmt.Fprintln(w)
	}

	// Reglas no evaluables (manuales / falta evidencia)
	if len(stats.NotEvaluated) > 0 {
		manual := []ctx.RuleResult{}
		falta := []ctx.RuleResult{}
		for _, r := range stats.NotEvaluated {
			if r.Status == ctx.StatusManualRequerido {
				manual = append(manual, r)
			} else {
				falta = append(falta, r)
			}
		}
		fmt.Fprintln(w, c(colorBlue)+c(colorBold)+" ▼ Pendientes de revisión / evidencia adicional:"+c(colorReset))
		if len(falta) > 0 {
			fmt.Fprintln(w, "   "+c(colorYellow)+"• Falta evidencia (entrada incompleta del usuario):"+c(colorReset))
			for _, r := range falta {
				fmt.Fprintf(w, "       [%s] %s\n", r.Rule.ID, truncate(r.Rule.Criterion, 80))
				if r.Notes != "" {
					fmt.Fprintf(w, "         %s↳ %s%s\n", c(colorGray), r.Notes, c(colorReset))
				}
			}
		}
		if len(manual) > 0 {
			fmt.Fprintln(w, "   "+c(colorBlue)+"• Requieren revisión humana:"+c(colorReset))
			// Ordenar por dominio + ID para que sea fácil de revisar
			sort.Slice(manual, func(i, j int) bool {
				if manual[i].Rule.Domain != manual[j].Rule.Domain {
					return manual[i].Rule.Domain < manual[j].Rule.Domain
				}
				return manual[i].Rule.ID < manual[j].Rule.ID
			})
			for _, r := range manual {
				fmt.Fprintf(w, "       [%s] %s\n", r.Rule.ID, truncate(r.Rule.Criterion, 80))
			}
		}
		fmt.Fprintln(w)
	}

	// Recomendaciones priorizadas
	recs := buildRecommendations(stats)
	if len(recs) > 0 {
		fmt.Fprintln(w, c(colorBold)+" ▼ Recomendaciones priorizadas:"+c(colorReset))
		for i, rec := range recs {
			fmt.Fprintf(w, "   %d. %s\n", i+1, rec)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, c(colorBold)+strings.Repeat("═", 78)+c(colorReset))
}

// PrintHistoryComparison muestra la evolución del score global a lo largo
// de las corridas guardadas para un mismo entorno.
func PrintHistoryComparison(w io.Writer, snapshots []scoring.Stats, names []string, useColor bool) {
	c := func(code string) string {
		if useColor {
			return code
		}
		return ""
	}
	fmt.Fprintln(w, c(colorBold)+"Evolución del Security Score:"+c(colorReset))
	for i, s := range snapshots {
		fmt.Fprintf(w, "  %s  %s%6.2f%s  apto=%v\n",
			names[i],
			c(colorBold)+scoreColor(s.GlobalScore, useColor),
			s.GlobalScore,
			c(colorReset),
			s.Apto,
		)
	}
}

// =====================================================================
// Helpers
// =====================================================================

func scoreColor(s float64, useColor bool) string {
	if !useColor {
		return ""
	}
	switch {
	case s >= 80:
		return colorGreen
	case s >= 60:
		return colorYellow
	default:
		return colorRed
	}
}

func severityColor(sev ctx.Severity, useColor bool) string {
	if !useColor {
		return ""
	}
	switch sev {
	case ctx.SevAlta:
		return colorRed
	case ctx.SevMedia:
		return colorYellow
	default:
		return colorGray
	}
}

func scoreBar(score float64, width int, useColor bool) string {
	filled := int(score / 100.0 * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if !useColor {
		return "[" + bar + "]"
	}
	return "[" + scoreColor(score, true) + bar + colorReset + "]"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func indent(s string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	lines := strings.Split(s, "\n")
	for i := 1; i < len(lines); i++ {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

// buildRecommendations produce 3-5 recomendaciones priorizadas por impacto.
func buildRecommendations(stats scoring.Stats) []string {
	out := []string{}

	if len(stats.CriticalFailures) > 0 {
		ids := []string{}
		for _, r := range stats.CriticalFailures {
			ids = append(ids, r.Rule.ID)
		}
		out = append(out, fmt.Sprintf("Cerrar de inmediato las SVR críticas (%s) antes de promover este entorno.", strings.Join(ids, ", ")))
	}

	if alta := stats.SeverityBreakdown[ctx.SevAlta]; alta > 0 {
		out = append(out, fmt.Sprintf("Priorizar las %d fallas de severidad alta del listado de hallazgos por el alto impacto sobre aislamiento, exposición o credenciales.", alta))
	}

	// Dominio con peor score sugiere foco
	worst := ctx.DomainNet
	worstScore := 100.01
	for _, d := range ctx.AllDomains() {
		if dc, ok := stats.DomainCounts[d]; ok && dc.Total > 0 && dc.Score < worstScore {
			worstScore = dc.Score
			worst = d
		}
	}
	if worstScore < 80 {
		out = append(out, fmt.Sprintf("Concentrar el siguiente ciclo de mejora en el dominio '%s' (score %.1f/100).", worst, worstScore))
	}

	if c := stats.StatusCounts[ctx.StatusFaltaEvidencia]; c > 0 {
		out = append(out, fmt.Sprintf("Completar los datos de configuración del cliente (%d reglas no se pudieron evaluar por falta de evidencia técnica).", c))
	}

	if c := stats.StatusCounts[ctx.StatusManualRequerido]; c > 0 {
		out = append(out, fmt.Sprintf("Coordinar con el equipo de infraestructura la revisión de %d reglas que requieren validación humana o acceso administrativo.", c))
	}

	return out
}
