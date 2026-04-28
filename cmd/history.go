package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	ctx "github.com/stagingshield/staging-shield/internal/context"
	"github.com/stagingshield/staging-shield/internal/report"
	"github.com/stagingshield/staging-shield/internal/scoring"
	"github.com/stagingshield/staging-shield/internal/storage"
)

var (
	histDirFlag    string
	histEnvFilter  string
	histLastN      int
	histNoColorH   bool
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Lista corridas previas y muestra la evolución del Security Score",
	Long: `Lee los snapshots JSON guardados por scan y muestra:

  · Tabla resumen de todas las corridas (fecha, entorno, score, apto).
  · Evolución temporal del score global filtrable por entorno.

Esto cumple SVR-MON-05 (corridas comparables que permiten ver tendencias).`,
	RunE: runHistory,
}

func init() {
	f := historyCmd.Flags()
	f.StringVar(&histDirFlag, "history-dir", "", "Directorio de historial (default: ~/.staging-shield/history)")
	f.StringVarP(&histEnvFilter, "env", "e", "", "Filtra por nombre de entorno")
	f.IntVarP(&histLastN, "last", "l", 0, "Muestra solo las últimas N corridas (0 = todas)")
	f.BoolVar(&histNoColorH, "no-color", false, "Desactiva colores en consola")
}

func runHistory(cmd *cobra.Command, args []string) error {
	dir := histDirFlag
	if dir == "" {
		dir = storage.DefaultDir()
	}

	var snapshots []storage.Snapshot
	var err error
	if histEnvFilter != "" {
		snapshots, err = storage.LoadByEnvironment(dir, histEnvFilter)
	} else {
		snapshots, err = storage.LoadAll(dir)
	}
	if err != nil {
		return fmt.Errorf("leyendo historial: %w", err)
	}

	if len(snapshots) == 0 {
		fmt.Println("No hay corridas previas en el historial.")
		fmt.Printf("Directorio inspeccionado: %s\n", dir)
		return nil
	}

	// Ordenar por fecha descendente para la tabla; ascendente para la evolución.
	sortedDesc := append([]storage.Snapshot{}, snapshots...)
	sort.Slice(sortedDesc, func(i, j int) bool {
		return sortedDesc[i].Timestamp.After(sortedDesc[j].Timestamp)
	})
	if histLastN > 0 && histLastN < len(sortedDesc) {
		sortedDesc = sortedDesc[:histLastN]
	}

	useColor := !histNoColorH && isTerminal(os.Stdout)

	printHistoryTable(sortedDesc, useColor)

	// Evolución (ascendente): solo si hay 2 o más en el filtro.
	if histEnvFilter != "" && len(snapshots) >= 2 {
		fmt.Println()
		printEvolution(snapshots, useColor)
	}

	return nil
}

func printHistoryTable(snaps []storage.Snapshot, useColor bool) {
	bold := ""
	reset := ""
	if useColor {
		bold = "\033[1m"
		reset = "\033[0m"
	}

	fmt.Printf("%s%-22s %-30s %-12s %8s %6s %14s%s\n",
		bold, "Fecha (UTC)", "Entorno", "Stack", "Score", "Apto", "Críticas NoCum", reset)
	fmt.Println(strings.Repeat("─", 100))

	for _, s := range snaps {
		apto := "✓"
		aptoColor := "\033[32m"
		if !s.Stats.Apto {
			apto = "✗"
			aptoColor = "\033[31m"
		}
		if !useColor {
			aptoColor = ""
		}
		closeC := ""
		if useColor {
			closeC = "\033[0m"
		}
		fmt.Printf("%-22s %-30s %-12s %8.2f %s%6s%s %14d\n",
			s.Timestamp.UTC().Format("2006-01-02 15:04:05"),
			truncate(s.Environment, 30),
			truncate(s.Stack, 12),
			s.Stats.GlobalScore,
			aptoColor, apto, closeC,
			len(s.Stats.CriticalFails),
		)
	}
}

func printEvolution(snaps []storage.Snapshot, useColor bool) {
	// Sintetizar []scoring.Stats + []string a partir de snapshots para
	// poder reutilizar PrintHistoryComparison del módulo de reporte.
	stats := make([]scoring.Stats, 0, len(snaps))
	names := make([]string, 0, len(snaps))
	for _, s := range snaps {
		stats = append(stats, scoring.Stats{
			GlobalScore: s.Stats.GlobalScore,
			Apto:        s.Stats.Apto,
			DomainScores: convertDomainScores(s.Stats.DomainScores),
		})
		names = append(names, s.Timestamp.UTC().Format("2006-01-02 15:04"))
	}
	report.PrintHistoryComparison(os.Stdout, stats, names, useColor)
}

func convertDomainScores(in map[string]float64) map[ctx.Domain]float64 {
	out := make(map[ctx.Domain]float64, len(in))
	for k, v := range in {
		out[ctx.Domain(k)] = v
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// silenciar import no usado de time si el linter quisiera quejarse
var _ = time.Now
