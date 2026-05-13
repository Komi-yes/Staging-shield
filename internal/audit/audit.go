// Package audit provides operator identity resolution, tool version detection,
// and SHA-256 hash-chain utilities for tamper-evident scan snapshots.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime/debug"
	"strings"
	"time"
)

// BuildVersion can be overridden at link time:
//
//	go build -ldflags "-X github.com/stagingshield/staging-shield/internal/audit.BuildVersion=v1.2.3"
var BuildVersion = "dev"

// Operator records who triggered a scan run.
type Operator struct {
	Name   string `json:"name"`
	Source string `json:"source"` // flag | env | git | os | none
}

// ToolInfo records which build of staging-shield produced the snapshot.
type ToolInfo struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Modified bool   `json:"modified,omitempty"`
}

// ResolveOperator resolves the operator identity with a fallback chain:
//  1. flagValue  — explicit --operator flag
//  2. STAGING_SHIELD_OPERATOR env var
//  3. git config user.email (inside repoPath, if provided)
//  4. OS username
//  5. "unknown"
func ResolveOperator(flagValue, repoPath string) Operator {
	if flagValue != "" {
		return Operator{Name: flagValue, Source: "flag"}
	}
	if v := os.Getenv("STAGING_SHIELD_OPERATOR"); v != "" {
		return Operator{Name: v, Source: "env"}
	}
	if repoPath != "" {
		if email := gitConfigEmail(repoPath); email != "" {
			return Operator{Name: email, Source: "git"}
		}
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return Operator{Name: u.Username, Source: "os"}
	}
	return Operator{Name: "unknown", Source: "none"}
}

func gitConfigEmail(repoPath string) string {
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}
	cmd := exec.Command("git", "-C", repoPath, "config", "user.email")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ResolveToolInfo reads build metadata from the Go runtime and the
// overridable BuildVersion variable.
func ResolveToolInfo() ToolInfo {
	ti := ToolInfo{Version: BuildVersion}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ti
	}

	// Use Module version when built as a module (go install / go build of a module).
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		ti.Version = info.Main.Version
	} else if BuildVersion == "dev" {
		ti.Version = "(devel)"
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 12 {
				ti.Revision = s.Value[:12]
			} else {
				ti.Revision = s.Value
			}
		case "vcs.modified":
			ti.Modified = s.Value == "true"
		}
	}
	return ti
}

// CanonicalHash returns the hex-encoded SHA-256 of the compact JSON encoding
// of v. Used by the storage package to compute integrity hashes without pulling
// the Snapshot type into this package (avoiding import cycles).
func CanonicalHash(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("audit: marshal for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ChainBreak describes a single integrity failure in the snapshot chain.
type ChainBreak struct {
	Index     int
	Timestamp time.Time
	Env       string
	Kind      string // hash-mismatch | prev-mismatch | missing-prev
	Detail    string
}

// SnapshotForChain is the minimal interface the chain verifier needs.
// The storage package satisfies this by constructing a slice of these.
type SnapshotForChain struct {
	Index         int
	Timestamp     time.Time
	Environment   string
	IntegrityHash string
	PrevHash      string
	// Payload is the full snapshot value (any), used to recompute the hash.
	// IntegrityHash must be empty in Payload when the hash was originally computed.
	Payload any
}

// VerifyChain walks snapshots (already sorted ascending by timestamp per env)
// and reports every integrity break. Pre-chain snapshots (IntegrityHash == "")
// are skipped and do not themselves constitute a break, but a chain-bearing
// snapshot that references a missing predecessor does.
func VerifyChain(snaps []SnapshotForChain) []ChainBreak {
	var breaks []ChainBreak
	prevHash := "" // hash of the last processed snapshot

	for _, s := range snaps {
		if s.IntegrityHash == "" {
			// Pre-chain snapshot: reset chain anchor, do not flag.
			prevHash = ""
			continue
		}

		// Recompute hash from payload.
		got, err := CanonicalHash(s.Payload)
		if err != nil {
			breaks = append(breaks, ChainBreak{
				Index:     s.Index,
				Timestamp: s.Timestamp,
				Env:       s.Environment,
				Kind:      "hash-mismatch",
				Detail:    "cannot recompute hash: " + err.Error(),
			})
			prevHash = s.IntegrityHash
			continue
		}
		if got != s.IntegrityHash {
			breaks = append(breaks, ChainBreak{
				Index:     s.Index,
				Timestamp: s.Timestamp,
				Env:       s.Environment,
				Kind:      "hash-mismatch",
				Detail:    fmt.Sprintf("stored=%s recomputed=%s", s.IntegrityHash[:12], got[:12]),
			})
		}

		// Check chain link.
		if s.PrevHash != prevHash {
			if prevHash == "" && s.PrevHash != "" {
				breaks = append(breaks, ChainBreak{
					Index:     s.Index,
					Timestamp: s.Timestamp,
					Env:       s.Environment,
					Kind:      "missing-prev",
					Detail:    fmt.Sprintf("references prev=%s but no prior snapshot found", s.PrevHash[:12]),
				})
			} else {
				expected := "<none>"
				if prevHash != "" {
					expected = prevHash[:12]
				}
				got12 := "<none>"
				if s.PrevHash != "" {
					got12 = s.PrevHash[:12]
				}
				breaks = append(breaks, ChainBreak{
					Index:     s.Index,
					Timestamp: s.Timestamp,
					Env:       s.Environment,
					Kind:      "prev-mismatch",
					Detail:    fmt.Sprintf("expected prev=%s got=%s", expected, got12),
				})
			}
		}

		prevHash = s.IntegrityHash
	}
	return breaks
}
