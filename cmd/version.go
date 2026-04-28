package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Muestra la versión del programa cliente",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Staging Shield v%s\n", Version)
		fmt.Printf("Plataforma: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Compilado con: %s\n", runtime.Version())
		fmt.Println("Catálogo SVR: 36 reglas (NET=10, HAR=10, IAM=8, MON=8)")
	},
}
