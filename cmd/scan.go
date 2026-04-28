package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stagingshield/staging-shield/internal/config"
	ctx "github.com/stagingshield/staging-shield/internal/context"
	"github.com/stagingshield/staging-shield/internal/discovery"
	"github.com/stagingshield/staging-shield/internal/report"
	"github.com/stagingshield/staging-shield/internal/rules"
	"github.com/stagingshield/staging-shield/internal/scoring"
	"github.com/stagingshield/staging-shield/internal/storage"
)

// Flags del subcomando scan
var (
	scanConfigPath  string
	scanEnvName     string
	scanStack       string
	scanDomain      string
	scanIP          string
	scanPorts       []int
	scanRepo        string
	scanProdRefs    []string
	scanAdminPorts  []string
	scanHTMLOut     string
	scanJSONHistory string
	scanHistoryDir  string
	scanNoColor     bool
	scanVerbose     bool
	scanNoSave      bool
	scanFailOnNoApt bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Ejecuta una evaluación completa del entorno de preproducción",
	Long: `El comando scan ejecuta los cinco módulos del modelo en orden:

  1. Entrada       — carga config (YAML y/o flags) y construye el contexto.
  2. Descubrimiento — DNS, puertos, TLS, HTTP, secretos, prod, admin, legacy.
  3. Validación    — aplica las 36 SVR contra la evidencia recolectada.
  4. Scoring       — calcula score global, score por dominio y aptitud.
  5. Reporte       — emite consola (siempre) + HTML/JSON opcionales.

Si no se proporciona --config, todos los datos del entorno deben venir por flags.
Si se proporciona --config, los flags lo sobreescriben campo a campo.`,
	RunE: runScan,
}

func init() {
	f := scanCmd.Flags()
	f.StringVarP(&scanConfigPath, "config", "c", "", "Ruta a archivo YAML de configuración del entorno")
	f.StringVarP(&scanEnvName, "name", "n", "", "Nombre del entorno (p.ej. 'staging-app-pagos')")
	f.StringVarP(&scanStack, "stack", "s", "", "Tipo de stack: web, api, container, k8s, etc. (default: web)")
	f.StringVarP(&scanDomain, "domain", "d", "", "Dominio objetivo (con o sin esquema)")
	f.StringVar(&scanIP, "ip", "", "IP del servidor objetivo")
	f.IntSliceVarP(&scanPorts, "ports", "p", nil, "Lista de puertos esperados, p.ej. 80,443,8080")
	f.StringVarP(&scanRepo, "repo", "r", "", "Ruta local al repositorio del proyecto (para detección de secretos)")
	f.StringSliceVar(&scanProdRefs, "prod-refs", nil, "IPs/hosts de producción (para validar aislamiento)")
	f.StringSliceVar(&scanAdminPorts, "admin-interfaces", nil, "Puertos/rutas administrativos esperados, p.ej. 9090,/admin")
	f.StringVar(&scanHTMLOut, "html-out", "", "Archivo de salida HTML (opcional)")
	f.StringVar(&scanJSONHistory, "json-out", "", "Archivo JSON adicional de salida (opcional, además del historial)")
	f.StringVar(&scanHistoryDir, "history-dir", "", "Directorio de historial (default: ~/.staging-shield/history)")
	f.BoolVar(&scanNoColor, "no-color", false, "Desactiva ANSI colors en salida de consola")
	f.BoolVarP(&scanVerbose, "verbose", "v", false, "Muestra trazas detalladas de descubrimiento")
	f.BoolVar(&scanNoSave, "no-save", false, "No guardar snapshot de historial en disco")
	f.BoolVar(&scanFailOnNoApt, "fail-on-noapt", false, "Devuelve exit code 2 si Apto=0 (útil en CI/CD)")
}

func runScan(cmd *cobra.Command, args []string) error {
	// 1. ENTRADA --------------------------------------------------------
	ec, err := buildContextFromFlagsAndConfig()
	if err != nil {
		return fmt.Errorf("entrada inválida: %w", err)
	}

	if scanVerbose {
		fmt.Printf("[entrada] Entorno=%s Target=%s IP=%s Repo=%s\n",
			ec.EnvironmentName, ec.Target, ec.IPAddress, ec.RepoPath)
	}

	// 2. DESCUBRIMIENTO -------------------------------------------------
	discovery.Run(ec, scanVerbose)

	// 3. VALIDACIÓN -----------------------------------------------------
	rules.Validate(ec)

	// 4. SCORING --------------------------------------------------------
	stats := scoring.Compute(ec, scoring.DefaultDomainWeights())

	// 5. REPORTE --------------------------------------------------------
	useColor := !scanNoColor && isTerminal(os.Stdout)
	report.PrintConsole(ec, stats, useColor)

	if scanHTMLOut != "" {
		if err := report.WriteHTML(scanHTMLOut, ec, stats); err != nil {
			fmt.Fprintf(os.Stderr, "Aviso: no se pudo escribir HTML (%v)\n", err)
		} else {
			fmt.Printf("\n📄 Reporte HTML: %s\n", scanHTMLOut)
		}
	}

	// Persistir historial (cumple SVR-MON-05: corridas comparables)
	if !scanNoSave {
		histDir := scanHistoryDir
		if histDir == "" {
			histDir = storage.DefaultDir()
		}
		if path, err := storage.Save(histDir, ec, stats); err != nil {
			fmt.Fprintf(os.Stderr, "Aviso: no se pudo guardar snapshot (%v)\n", err)
		} else if scanVerbose {
			fmt.Printf("[storage] snapshot: %s\n", path)
		}
	}

	// JSON de salida adicional (útil para integración CI)
	if scanJSONHistory != "" {
		dir := scanJSONHistory
		// Si se pasó un archivo, escribir a su directorio
		if !strings.HasSuffix(dir, string(os.PathSeparator)) {
			// tratamos scanJSONHistory como ruta de archivo: usar Save y renombrar es complejo;
			// más simple: escribir directamente.
			if err := writeJSONExport(scanJSONHistory, ec, stats); err != nil {
				fmt.Fprintf(os.Stderr, "Aviso: no se pudo escribir JSON (%v)\n", err)
			} else {
				fmt.Printf("📦 Export JSON: %s\n", scanJSONHistory)
			}
		}
	}

	// Exit code 2 si Apto=0 y se pidió fail-on-noapt (para integración CI/CD)
	if scanFailOnNoApt && !stats.Apto {
		os.Exit(2)
	}

	return nil
}

// buildContextFromFlagsAndConfig combina el archivo YAML (si existe) con los
// flags de la CLI. Los flags tienen prioridad sobre el archivo.
func buildContextFromFlagsAndConfig() (*ctx.EvalContext, error) {
	if scanConfigPath != "" {
		ec, err := config.Load(scanConfigPath)
		if err != nil {
			return nil, err
		}
		// Aplicar overrides de flags
		if scanEnvName != "" {
			ec.EnvironmentName = scanEnvName
		}
		if scanStack != "" {
			ec.StackType = scanStack
		}
		if scanDomain != "" {
			ec.Target = strings.TrimPrefix(strings.TrimPrefix(scanDomain, "https://"), "http://")
		}
		if scanIP != "" {
			ec.IPAddress = scanIP
		}
		if len(scanPorts) > 0 {
			ec.ExpectedPorts = scanPorts
		}
		if scanRepo != "" {
			ec.RepoPath = scanRepo
		}
		if len(scanProdRefs) > 0 {
			ec.ProductionRefs = scanProdRefs
		}
		if len(scanAdminPorts) > 0 {
			ec.AdminInterfaces = scanAdminPorts
		}
		return ec, nil
	}

	// Sin archivo: construir desde flags exclusivamente
	if scanEnvName == "" {
		return nil, fmt.Errorf("debe proporcionar --name o --config")
	}
	if scanDomain == "" && scanIP == "" {
		return nil, fmt.Errorf("debe proporcionar --domain o --ip (o --config)")
	}
	stack := scanStack
	if stack == "" {
		stack = "web"
	}
	ec, err := config.BuildFromFlags(scanEnvName, stack, scanDomain, scanIP, scanPorts, scanRepo, scanProdRefs)
	if err != nil {
		return nil, err
	}
	if len(scanAdminPorts) > 0 {
		ec.AdminInterfaces = scanAdminPorts
	}
	return ec, nil
}

// writeJSONExport escribe un export JSON en formato similar al historial pero
// en una ruta arbitraria (independiente del directorio de historial).
func writeJSONExport(path string, ec *ctx.EvalContext, stats scoring.Stats) error {
	// Reutilizamos storage.Save indirectamente: copiamos el snapshot al path indicado.
	// Como Save genera nombre automático, replicamos la lógica aquí en pequeño.
	dir := "."
	tmp, err := storage.Save(os.TempDir(), ec, stats)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	_ = dir // silenciar
	return os.WriteFile(path, data, 0o644)
}
