// Package cmd implementa la interfaz de línea de comandos de Staging Shield
// usando Cobra. Expone los subcomandos `scan`, `history` y `version`.
package cmd

import (
	"github.com/spf13/cobra"
)

// Version del programa cliente. Se incrementa al cambiar el catálogo de SVR
// o el modelo de scoring.
const Version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "staging-shield",
	Short: "Staging Shield — Modelo de Evaluación de Seguridad para Entornos de Preproducción",
	Long: `Staging Shield evalúa entornos de preproducción (staging) contra un catálogo
de 36 Security Verification Rules (SVR) distribuidas en cuatro dominios:

  · Red y aislamiento (NET)
  · Hardening de host y plataforma (HAR)
  · Identidades, acceso y secretos (IAM)
  · Monitoreo, integridad y trazabilidad (MON)

El programa automatiza el descubrimiento (DNS, puertos, TLS, cabeceras HTTP,
secretos en repositorio, conectividad a producción, interfaces administrativas)
y aplica la fórmula:

  Score = 100 × Σ(c · w · d) ÷ Σ(w · d)

Las SVR críticas que queden en estado "no cumple" producen Apto=0 y bloquean
la promoción del entorno, independientemente del score numérico.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute es el punto de entrada que main() invoca.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(auditCmd)
}
