// Package storage persiste las corridas en disco como archivos JSON.
// Esto cumple SVR-MON-05 (historial comparable) y permite generar la
// vista de evolución temporal del entorno.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	ctx "github.com/stagingshield/staging-shield/internal/context"
	"github.com/stagingshield/staging-shield/internal/scoring"
)

// Snapshot es lo que se guarda en disco para cada corrida.
type Snapshot struct {
	Version     string            `json:"version"`
	Environment string            `json:"environment"`
	Stack       string            `json:"stack"`
	Target      string            `json:"target"`
	Timestamp   time.Time         `json:"timestamp"`
	Stats       SnapshotStats     `json:"stats"`
	Results     []ctx.RuleResult  `json:"results"`
	Discovery   ctx.DiscoveryData `json:"discovery"`
}

// SnapshotStats es la versión serializable de scoring.Stats.
type SnapshotStats struct {
	GlobalScore   float64                   `json:"global_score"`
	DomainScores  map[string]float64        `json:"domain_scores"`
	Apto          bool                      `json:"apto"`
	AutoCoverage  float64                   `json:"auto_coverage"`
	StatusCounts  map[string]int            `json:"status_counts"`
	CriticalFails []string                  `json:"critical_failures"` // IDs
}

// DefaultDir es el directorio donde se guardan los reportes JSON.
func DefaultDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".staging-shield", "history")
	}
	return ".staging-shield/history"
}

// Save serializa la corrida actual a un archivo JSON único.
func Save(dir string, ec *ctx.EvalContext, stats scoring.Stats) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creando directorio de historial: %w", err)
	}

	snap := buildSnapshot(ec, stats)

	envSlug := slugify(ec.EnvironmentName)
	stamp := ec.Timestamp.UTC().Format("20060102T150405Z")
	filename := fmt.Sprintf("%s-%s.json", envSlug, stamp)
	full := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", fmt.Errorf("serializando snapshot: %w", err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		return "", fmt.Errorf("escribiendo snapshot: %w", err)
	}
	return full, nil
}

// LoadAll devuelve todas las corridas guardadas, ordenadas por timestamp asc.
func LoadAll(dir string) ([]Snapshot, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []Snapshot{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var s Snapshot
		if err := json.Unmarshal(data, &s); err != nil {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Timestamp.Before(out[j].Timestamp)
	})
	return out, nil
}

// LoadByEnvironment filtra el historial por nombre de entorno.
func LoadByEnvironment(dir, env string) ([]Snapshot, error) {
	all, err := LoadAll(dir)
	if err != nil {
		return nil, err
	}
	out := []Snapshot{}
	want := strings.ToLower(env)
	for _, s := range all {
		if strings.ToLower(s.Environment) == want {
			out = append(out, s)
		}
	}
	return out, nil
}

func buildSnapshot(ec *ctx.EvalContext, stats scoring.Stats) Snapshot {
	domScores := make(map[string]float64, len(stats.DomainScores))
	for d, s := range stats.DomainScores {
		domScores[string(d)] = s
	}
	statusCounts := make(map[string]int, len(stats.StatusCounts))
	for s, n := range stats.StatusCounts {
		statusCounts[s.String()] = n
	}
	crit := make([]string, 0, len(stats.CriticalFailures))
	for _, r := range stats.CriticalFailures {
		crit = append(crit, r.Rule.ID)
	}

	return Snapshot{
		Version:     "1.0",
		Environment: ec.EnvironmentName,
		Stack:       ec.StackType,
		Target:      ec.Target,
		Timestamp:   ec.Timestamp,
		Stats: SnapshotStats{
			GlobalScore:   stats.GlobalScore,
			DomainScores:  domScores,
			Apto:          stats.Apto,
			AutoCoverage:  stats.AutoCoverage,
			StatusCounts:  statusCounts,
			CriticalFails: crit,
		},
		Results:   ec.Results,
		Discovery: ec.Discovery,
	}
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	out := strings.Builder{}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == ' ', r == '_', r == '-':
			out.WriteRune('-')
		}
	}
	res := out.String()
	if res == "" {
		res = "env"
	}
	return res
}
