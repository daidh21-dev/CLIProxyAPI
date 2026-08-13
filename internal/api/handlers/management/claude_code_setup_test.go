package management

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestNormalizeClaudeCodeBaseURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "adds v1", in: "http://localhost:8317", want: "http://localhost:8317/v1"},
		{name: "keeps v1", in: "http://localhost:8317/v1", want: "http://localhost:8317/v1"},
		{name: "trims slash", in: "http://localhost:8317/", want: "http://localhost:8317/v1"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeClaudeCodeBaseURL(tt.in); got != tt.want {
				t.Fatalf("normalizeClaudeCodeBaseURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestWriteClaudeCodeSettingsMergesEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	if errMkdir := os.MkdirAll(filepath.Dir(path), 0o700); errMkdir != nil {
		t.Fatalf("mkdir: %v", errMkdir)
	}
	initial := map[string]any{"env": map[string]any{"OTHER": "keep", "CLAUDE_CODE_MAX_CONTEXT_TOKENS": "200000"}}
	data, _ := json.Marshal(initial)
	if errWrite := os.WriteFile(path, data, 0o600); errWrite != nil {
		t.Fatalf("write initial: %v", errWrite)
	}

	err := writeClaudeCodeSettings(path, map[string]string{
		"ANTHROPIC_BASE_URL":             "http://localhost:8317",
		"ANTHROPIC_AUTH_TOKEN":           "sk-test",
		"CLAUDE_CODE_MAX_CONTEXT_TOKENS": "",
	})
	if err != nil {
		t.Fatalf("writeClaudeCodeSettings() error = %v", err)
	}
	settings, errRead := readClaudeCodeJSONMap(path)
	if errRead != nil {
		t.Fatalf("read settings: %v", errRead)
	}
	env := claudeCodeEnvMap(settings)
	if got := env["ANTHROPIC_BASE_URL"]; got != "http://localhost:8317/v1" {
		t.Fatalf("ANTHROPIC_BASE_URL = %q", got)
	}
	if got := env["ANTHROPIC_AUTH_TOKEN"]; got != "sk-test" {
		t.Fatalf("ANTHROPIC_AUTH_TOKEN = %q", got)
	}
	if got := env["OTHER"]; got != "keep" {
		t.Fatalf("OTHER = %q", got)
	}
	if _, ok := env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"]; ok {
		t.Fatalf("CLAUDE_CODE_MAX_CONTEXT_TOKENS should be removed")
	}
	if got, _ := settings["hasCompletedOnboarding"].(bool); !got {
		t.Fatalf("hasCompletedOnboarding should be true")
	}
}

func TestResetClaudeCodeSettingsRemovesManagedEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	if errMkdir := os.MkdirAll(filepath.Dir(path), 0o700); errMkdir != nil {
		t.Fatalf("mkdir: %v", errMkdir)
	}
	initial := map[string]any{"env": map[string]any{"ANTHROPIC_BASE_URL": "http://localhost:8317/v1", "OTHER": "keep"}}
	data, _ := json.Marshal(initial)
	if errWrite := os.WriteFile(path, data, 0o600); errWrite != nil {
		t.Fatalf("write initial: %v", errWrite)
	}
	if errReset := resetClaudeCodeSettings(path); errReset != nil {
		t.Fatalf("resetClaudeCodeSettings() error = %v", errReset)
	}
	settings, errRead := readClaudeCodeJSONMap(path)
	if errRead != nil {
		t.Fatalf("read settings: %v", errRead)
	}
	env := claudeCodeEnvMap(settings)
	if _, ok := env["ANTHROPIC_BASE_URL"]; ok {
		t.Fatalf("ANTHROPIC_BASE_URL should be removed")
	}
	if got := env["OTHER"]; got != "keep" {
		t.Fatalf("OTHER = %q", got)
	}
}

func TestWriteClaudeCodeExaMCP(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude.json")
	if errWrite := writeClaudeCodeExaMCP(path, true); errWrite != nil {
		t.Fatalf("enable Exa MCP: %v", errWrite)
	}
	data, errRead := readClaudeCodeJSONMap(path)
	if errRead != nil {
		t.Fatalf("read claude json: %v", errRead)
	}
	if !claudeCodeExaMCPEnabled(data) {
		t.Fatalf("Exa MCP should be enabled")
	}
	if errWrite := writeClaudeCodeExaMCP(path, false); errWrite != nil {
		t.Fatalf("disable Exa MCP: %v", errWrite)
	}
	data, errRead = readClaudeCodeJSONMap(path)
	if errRead != nil {
		t.Fatalf("read claude json: %v", errRead)
	}
	if claudeCodeExaMCPEnabled(data) {
		t.Fatalf("Exa MCP should be disabled")
	}
}

func TestClaudeCodeModelOptionsPreferAliasesByFamily(t *testing.T) {
	h := &Handler{cfg: &config.Config{ClaudeKey: []config.ClaudeKey{
		{Models: []config.ClaudeModel{
			{Name: "upstream-opus", Alias: "team/claude-opus-best"},
			{Name: "claude-sonnet-4", Alias: "team/sonnet"},
			{Name: "claude-haiku-4"},
		}},
	}}}
	models, defaults := h.claudeCodeModelOptions()
	if len(models) != 3 {
		t.Fatalf("model count = %d, want 3", len(models))
	}
	if got := defaults["opus"]; got != "team/claude-opus-best" {
		t.Fatalf("opus default = %q", got)
	}
	if got := defaults["sonnet"]; got != "team/sonnet" {
		t.Fatalf("sonnet default = %q", got)
	}
	if got := defaults["haiku"]; got != "claude-haiku-4" {
		t.Fatalf("haiku default = %q", got)
	}
}
