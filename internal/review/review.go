// Package review carga, valida y aplica los veredictos manuales que un
// evaluador humano emite sobre las SVR. Existe para cumplir con dos cosas:
//
//  1. SVR-MON-08 — diferenciar "no cumple" de "falta de evidencia": una
//     regla manual no se cuenta como falla, pero tampoco se sigue dejando
//     en pendiente indefinida si el evaluador ya la revisó.
//  2. La cobertura del modelo (definida en el documento) requiere que los
//     veredictos humanos también sumen al puntaje. Sin esto, las 13+ reglas
//     manuales del catálogo quedan permanentemente fuera del cálculo.
//
// El archivo de revisión se diseña para ser editable a mano (YAML), pero
// también el HTML del reporte exporta el mismo formato cuando el usuario
// completa la verificación interactiva.
package review

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	ctx "github.com/stagingshield/staging-shield/internal/context"
)

// File representa el contenido de un archivo de revisión manual.
type File struct {
	Reviewer  string             `yaml:"reviewer,omitempty"`
	Timestamp time.Time          `yaml:"timestamp,omitempty"`
	Verdicts  map[string]Verdict `yaml:"verdicts"`
}

// Verdict es la decisión humana sobre una SVR específica. El campo Status
// usa cadenas legibles para que el archivo sea editable sin consultar
// constantes de Go.
type Verdict struct {
	Status   string `yaml:"status"`             // "cumple" | "cumple_parcial" | "no_cumple" | "no_aplica"
	Evidence string `yaml:"evidence,omitempty"` // texto libre con la evidencia humana
	Notes    string `yaml:"notes,omitempty"`    // notas adicionales
}

// Load lee y valida un archivo YAML de revisión.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer archivo de revisión: %w", err)
	}
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("YAML de revisión inválido: %w", err)
	}
	if len(f.Verdicts) == 0 {
		return nil, fmt.Errorf("el archivo de revisión no contiene veredictos")
	}
	for id, v := range f.Verdicts {
		if _, ok := parseStatus(v.Status); !ok && !strings.EqualFold(v.Status, "no_aplica") {
			return nil, fmt.Errorf("veredicto inválido para %s: status=%q (esperado cumple|cumple_parcial|no_cumple|no_aplica)", id, v.Status)
		}
	}
	return &f, nil
}

// Apply sobreescribe los resultados según los veredictos del archivo.
//
// Reglas de aplicación:
//
//   - Solo se sobreescriben reglas en estado StatusManualRequerido o
//     StatusFaltaEvidencia. Las reglas que el motor automático ya resolvió
//     NO se sobreescriben para evitar que un veredicto humano "olvide"
//     hallazgos técnicos detectados.
//   - Si el evaluador desea forzar override de una regla automática, debe
//     usar el sufijo "_force" en el status (ej: "cumple_force"). En ese
//     caso queda registrado en el ManualVerdict para auditoría.
//   - "no_aplica" se traduce a StatusFaltaEvidencia con una nota explícita;
//     no contamina el score (el cálculo lo descarta) y queda visible en el
//     reporte como "no aplica al stack del entorno".
//
// Devuelve la cantidad de reglas sobreescritas y la lista de IDs no
// encontrados (útil para advertir al usuario sobre typos en el archivo).
func Apply(results []ctx.RuleResult, rev *File) (overridden int, unknownIDs []string) {
	if rev == nil {
		return 0, nil
	}
	known := make(map[string]int, len(results)) // id -> índice
	for i, r := range results {
		known[r.Rule.ID] = i
	}

	for id, v := range rev.Verdicts {
		idx, ok := known[id]
		if !ok {
			unknownIDs = append(unknownIDs, id)
			continue
		}
		current := results[idx]
		isManualSlot := current.Status == ctx.StatusManualRequerido ||
			current.Status == ctx.StatusFaltaEvidencia

		statusStr := v.Status
		force := false
		if strings.HasSuffix(statusStr, "_force") {
			statusStr = strings.TrimSuffix(statusStr, "_force")
			force = true
		}

		// Solo aplica si la regla está en slot manual o se forzó override.
		if !isManualSlot && !force {
			continue
		}

		if strings.EqualFold(statusStr, "no_aplica") {
			results[idx].Status = ctx.StatusFaltaEvidencia
			results[idx].Notes = "Marcada como 'no aplica' por el evaluador. " + v.Notes
			results[idx].Evidence = v.Evidence
			results[idx].Manual = &ctx.ManualVerdict{
				Reviewer:   rev.Reviewer,
				ReviewedAt: rev.Timestamp,
				Evidence:   v.Evidence,
				Notes:      "no_aplica: " + v.Notes,
			}
			overridden++
			continue
		}

		st, ok := parseStatus(statusStr)
		if !ok {
			continue
		}
		results[idx].Status = st
		results[idx].Evidence = v.Evidence
		if v.Notes != "" {
			results[idx].Notes = v.Notes
		}
		results[idx].Manual = &ctx.ManualVerdict{
			Reviewer:   rev.Reviewer,
			ReviewedAt: rev.Timestamp,
			Evidence:   v.Evidence,
			Notes:      v.Notes,
		}
		overridden++
	}
	return overridden, unknownIDs
}

func parseStatus(s string) (ctx.ComplianceStatus, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "cumple":
		return ctx.StatusCumple, true
	case "cumple_parcial", "cumple_parcialmente", "parcial":
		return ctx.StatusCumpleParcial, true
	case "no_cumple", "no-cumple", "nocumple":
		return ctx.StatusNoCumple, true
	}
	return ctx.StatusPendiente, false
}
