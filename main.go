// Staging Shield - Modelo de Evaluación de Seguridad para Entornos de Preproducción
// Programa cliente que automatiza la verificación de Security Verification Rules (SVR)
// y calcula el Security Score conforme al modelo descrito en el documento del proyecto.
package main

import (
	"fmt"
	"os"

	"github.com/stagingshield/staging-shield/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
