package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stagingshield/staging-shield/internal/audit"
	"github.com/stagingshield/staging-shield/internal/storage"
)

var (
	auditHistoryDir string
	auditEnvFilter  string
	auditNoColorA   bool
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Herramientas de auditoría de corridas (cadena de integridad, identidad de operador)",
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verifica la cadena de integridad SHA-256 de los snapshots almacenados",
	Long: `Recorre los snapshots guardados por scan (o los de un entorno específico con --env)
y verifica que:

  1. El hash SHA-256 de cada snapshot coincide con el valor almacenado en integrity_hash.
  2. El campo prev_hash apunta correctamente al hash del snapshot anterior del mismo entorno.

Cualquier edición o borrado de un snapshot rompe la cadena y se identifica aquí.
Los snapshots anteriores a la introducción de la cadena (sin integrity_hash) se marcan
como "pre-chain" y no constituyen una ruptura por sí solos.

Exit codes:
  0 — cadena intacta (o sin snapshots con cadena).
  3 — cadena rota; se muestra el primer snapshot afectado.`,
	RunE: runAuditVerify,
}

func init() {
	f := auditVerifyCmd.Flags()
	f.StringVar(&auditHistoryDir, "history-dir", "", "Directorio de historial (default: ~/.staging-shield/history)")
	f.StringVarP(&auditEnvFilter, "env", "e", "", "Verifica solo el entorno indicado")
	f.BoolVar(&auditNoColorA, "no-color", false, "Desactiva colores ANSI")

	auditCmd.AddCommand(auditVerifyCmd)
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	dir := auditHistoryDir
	if dir == "" {
		dir = storage.DefaultDir()
	}

	var (
		snaps []storage.Snapshot
		err   error
	)
	if auditEnvFilter != "" {
		snaps, err = storage.LoadByEnvironment(dir, auditEnvFilter)
	} else {
		snaps, err = storage.LoadAll(dir)
	}
	if err != nil {
		return fmt.Errorf("leyendo historial: %w", err)
	}

	if len(snaps) == 0 {
		fmt.Println("No hay snapshots en el historial.")
		fmt.Printf("Directorio inspeccionado: %s\n", dir)
		return nil
	}

	// Group by environment and sort each group ascending so the chain
	// is walked in chronological order per environment.
	byEnv := make(map[string][]storage.Snapshot)
	for _, s := range snaps {
		byEnv[s.Environment] = append(byEnv[s.Environment], s)
	}
	for env := range byEnv {
		sort.Slice(byEnv[env], func(i, j int) bool {
			return byEnv[env][i].Timestamp.Before(byEnv[env][j].Timestamp)
		})
	}

	// Stable environment order.
	envs := make([]string, 0, len(byEnv))
	for e := range byEnv {
		envs = append(envs, e)
	}
	sort.Strings(envs)

	useColor := !auditNoColorA && isTerminal(os.Stdout)
	green := ansiWrap(useColor, "\033[32m")
	red := ansiWrap(useColor, "\033[31m")
	yellow := ansiWrap(useColor, "\033[33m")
	reset := ansiWrap(useColor, "\033[0m")
	bold := ansiWrap(useColor, "\033[1m")

	fmt.Printf("%s%-22s %-30s %-20s %-10s %-14s %s%s\n",
		bold, "Fecha (UTC)", "Entorno", "Operador", "Versión", "Hash (12)", "Estado", reset)
	fmt.Println(strings.Repeat("─", 110))

	allBreaks := []audit.ChainBreak{}

	for _, env := range envs {
		group := byEnv[env]
		chain := storage.SnapshotsForChain(group)
		breaks := audit.VerifyChain(chain)
		breakIdx := make(map[int]audit.ChainBreak)
		for _, b := range breaks {
			breakIdx[b.Index] = b
		}
		allBreaks = append(allBreaks, breaks...)

		for i, s := range group {
			short := func(h string) string {
				if len(h) >= 12 {
					return h[:12]
				}
				if h == "" {
					return "—"
				}
				return h
			}

			status := green + "OK" + reset
			if s.IntegrityHash == "" {
				status = yellow + "pre-chain" + reset
			}
			if b, broken := breakIdx[i]; broken {
				status = red + "ROTO: " + b.Kind + reset
			}

			fmt.Printf("%-22s %-30s %-20s %-10s %-14s %s\n",
				s.Timestamp.UTC().Format("2006-01-02 15:04:05"),
				truncate(s.Environment, 30),
				truncate(s.Operator.Name, 20),
				truncate(s.Tool.Version, 10),
				short(s.IntegrityHash),
				status,
			)
		}
	}

	if len(allBreaks) > 0 {
		fmt.Println()
		fmt.Printf("%sCadena rota: %d ruptura(s) detectada(s).%s\n", red, len(allBreaks), reset)
		for _, b := range allBreaks {
			fmt.Printf("  · [%s] %s — %s: %s\n",
				b.Timestamp.UTC().Format("2006-01-02 15:04:05"),
				b.Env, b.Kind, b.Detail)
		}
		os.Exit(3)
	}

	chainCount := 0
	for _, s := range snaps {
		if s.IntegrityHash != "" {
			chainCount++
		}
	}
	if chainCount > 0 {
		fmt.Printf("\n%sCadena de integridad verificada: %d snapshot(s) OK.%s\n", green, chainCount, reset)
	} else {
		fmt.Printf("\n%sTodos los snapshots son pre-chain (no hay integridad que verificar).%s\n", yellow, reset)
	}
	return nil
}

func ansiWrap(useColor bool, code string) string {
	if useColor {
		return code
	}
	return ""
}
