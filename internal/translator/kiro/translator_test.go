package kiro

import (
	"encoding/json"
	"testing"
)

func TestTranslateToKiroRequest(t *testing.T) {
	temperature := 0.2
	openAIReq := map[string]any{
		"model":       "kiro/claude-sonnet-4.5-thinking",
		"max_tokens":  123,
		"temperature": temperature,
		"messages": []map[string]any{
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Write a hello world in Go."},
		},
	}

	rawBody, _ := json.Marshal(openAIReq)
	translated, cleanModel, err := TranslateToKiroRequest(rawBody, "arn:aws:codewhisperer:us-east-1:123:profile")
	if err != nil {
		t.Fatalf("failed to translate request: %v", err)
	}

	if cleanModel != "claude-sonnet-4.5" {
		t.Errorf("expected cleanModel 'claude-sonnet-4.5', got '%s'", cleanModel)
	}

	var res KiroGenerateRequest
	if err := json.Unmarshal(translated, &res); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if res.ProfileArn != "arn:aws:codewhisperer:us-east-1:123:profile" {
		t.Errorf("profileArn mismatch")
	}

	if res.ConversationState.CurrentMessage.UserInputMessage.Content == "" {
		t.Errorf("expected non-empty user message content")
	}
	if res.InferenceConfig == nil || res.InferenceConfig.MaxTokens != 123 {
		t.Fatalf("expected inference config with max tokens")
	}
}

func TestCleanKiroModelIDAliases(t *testing.T) {
	tests := map[string]string{
		"kiro/claude-sonnet-4.5-thinking": "claude-sonnet-4.5",
		"claude-sonnet-4-20250514":        "claude-sonnet-4",
		"claude-3-5-sonnet":               "claude-sonnet-4.5",
		"claude-sonnet-4-5":               "claude-sonnet-4.5",
		"claude-haiku-4-5":                "claude-haiku-4.5",
	}
	for input, want := range tests {
		if got := CleanKiroModelID(input); got != want {
			t.Fatalf("CleanKiroModelID(%q) = %q, want %q", input, got, want)
		}
	}
}
