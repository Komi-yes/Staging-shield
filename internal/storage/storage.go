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

	"github.com/stagingshield/staging-shield/internal/audit"
	ctx "github.com/stagingshield/staging-shield/internal/context"
	"github.com/stagingshield/staging-shield/internal/scoring"
)

// Snapshot es lo que se guarda en disco para cada corrida.
type Snapshot struct {
	Version       string            `json:"version"`
	Environment   string            `json:"environment"`
	Stack         string            `json:"stack"`
	Target        string            `json:"target"`
	Timestamp     time.Time         `json:"timestamp"`
	Operator      audit.Operator    `json:"operator"`
	Tool          audit.ToolInfo    `json:"tool"`
	Stats         SnapshotStats     `json:"stats"`
	Results       []ctx.RuleResult  `json:"results"`
	Discovery     ctx.DiscoveryData `json:"discovery"`
	PrevHash      string            `json:"prev_hash,omitempty"`
	IntegrityHash string            `json:"integrity_hash,omitempty"`
}

// SnapshotStats es la versión serializable de scoring.Stats.
type SnapshotStats struct {
	GlobalScore      float64            `json:"global_score"`
	DomainScores     map[string]float64 `json:"domain_scores"`
	Apto             bool               `json:"apto"`
	AutoCoverage     float64            `json:"auto_coverage"`
	ManualCoverage   float64            `json:"manual_coverage"`
	Coverage         float64            `json:"coverage"`
	ManuallyReviewed int                `json:"manually_reviewed"`
	EvaluatedRules   int                `json:"evaluated_rules"`
	StatusCounts     map[string]int     `json:"status_counts"`
	CriticalFails    []string           `json:"critical_failures"` // IDs
}

// DefaultDir es el directorio donde se guardan los reportes JSON.
func DefaultDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".staging-shield", "history")
	}
	return ".staging-shield/history"
}

// Save serializa la corrida actual a un archivo JSON único con encadenamiento
// SHA-256 para detectar ediciones o borrados posteriores.
func Save(dir string, ec *ctx.EvalContext, stats scoring.Stats, op audit.Operator, tool audit.ToolInfo) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creando directorio de historial: %w", err)
	}

	snap := buildSnapshot(ec, stats, op, tool)

	// Resolve PrevHash: find the most recent snapshot for this environment.
	envSlug := slugify(ec.EnvironmentName)
	if prev := latestSnapshotForEnv(dir, envSlug); prev != nil {
		snap.PrevHash = prev.IntegrityHash
	}

	// Compute integrity hash (with IntegrityHash field empty).
	h, err := audit.CanonicalHash(snap)
	if err != nil {
		return "", fmt.Errorf("computando hash de integridad: %w", err)
	}
	snap.IntegrityHash = h

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

// latestSnapshotForEnv returns the most recent on-disk snapshot for the given
// environment slug, or nil if none exists. Filenames are timestamped UTC so
// lexicographic max == chronological max.
func latestSnapshotForEnv(dir, envSlug string) *Snapshot {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	prefix := envSlug + "-"
	latest := ""
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if strings.HasPrefix(e.Name(), prefix) && e.Name() > latest {
			latest = e.Name()
		}
	}
	if latest == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, latest))
	if err != nil {
		return nil
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	return &s
}

// ReadSnapshot reads a single snapshot from a file path.
func ReadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
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

func buildSnapshot(ec *ctx.EvalContext, stats scoring.Stats, op audit.Operator, tool audit.ToolInfo) Snapshot {
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
		Version:     "1.2",
		Environment: ec.EnvironmentName,
		Stack:       ec.StackType,
		Target:      ec.Target,
		Timestamp:   ec.Timestamp,
		Operator:    op,
		Tool:        tool,
		Stats: SnapshotStats{
			GlobalScore:      stats.GlobalScore,
			DomainScores:     domScores,
			Apto:             stats.Apto,
			AutoCoverage:     stats.AutoCoverage,
			ManualCoverage:   stats.ManualCoverage,
			Coverage:         stats.Coverage,
			ManuallyReviewed: stats.ManuallyReviewed,
			EvaluatedRules:   stats.EvaluatedRules,
			StatusCounts:     statusCounts,
			CriticalFails:    crit,
		},
		Results:   ec.Results,
		Discovery: ec.Discovery,
	}
}

// SnapshotsForChain converts a sorted slice of Snapshots into the minimal
// representation that audit.VerifyChain requires. The Payload for each entry
// is a copy of the snapshot with IntegrityHash cleared, matching the state
// the hash was originally computed over.
func SnapshotsForChain(snaps []Snapshot) []audit.SnapshotForChain {
	out := make([]audit.SnapshotForChain, len(snaps))
	for i, s := range snaps {
		payload := s
		payload.IntegrityHash = ""
		out[i] = audit.SnapshotForChain{
			Index:         i,
			Timestamp:     s.Timestamp,
			Environment:   s.Environment,
			IntegrityHash: s.IntegrityHash,
			PrevHash:      s.PrevHash,
			Payload:       payload,
		}
	}
	return out
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
