package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/tidwall/gjson"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestKiroEstimateInputTokensNonZero(t *testing.T) {
	payload := []byte(`{"model":"claude-opus-5.5","system":"You are a helpful assistant.","messages":[{"role":"user","content":"` + strings.Repeat("hello world ", 500) + `"}]}`)
	if n := kiroEstimateInputTokens(payload); n < 900 {
		t.Fatalf("expected ~1000 input tokens, got %d", n)
	}
}

func TestStreamClaudeFromKiroReportsUsage(t *testing.T) {
	out := make(chan cliproxyexecutor.StreamChunk, 64)
	// Empty upstream body: parser returns an error after message_start is sent,
	// which is enough to verify the message_start usage.
	streamClaudeFromKiro(context.Background(), strings.NewReader(""), out, "claude-opus-5.5", 12345)
	close(out)
	first := <-out
	data := string(first.Payload)
	idx := strings.Index(data, "data: ")
	if idx < 0 {
		t.Fatalf("no data line: %q", data)
	}
	got := gjson.Get(strings.TrimSpace(data[idx+6:]), "message.usage.input_tokens").Int()
	if got != 12345 {
		t.Fatalf("message_start input_tokens = %d, want 12345", got)
	}
}

func TestKiroCountTokens(t *testing.T) {
	e := &KiroExecutor{}
	resp, err := e.CountTokens(context.Background(), nil, cliproxyexecutor.Request{Payload: []byte(`{"messages":[{"role":"user","content":"hello there"}]}`)}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if gjson.GetBytes(resp.Payload, "input_tokens").Int() <= 0 {
		t.Fatalf("unexpected count payload: %s", resp.Payload)
	}
}
