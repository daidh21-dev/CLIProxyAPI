package kiro

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTruncationKeepsRecentHistoryFromRealSession feeds a real 1.4MB Claude Code
// request (268 messages) through the translator. Before the fix, exceeding
// maxPayloadBytes dropped the entire history (including the system prompt),
// leaving only the truncation placeholder.
func TestTruncationKeepsRecentHistoryFromRealSession(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "reproduce_orphan_toolresult.json"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	out, _, err := TranslateToKiroRequest(raw, "arn")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > maxPayloadBytes {
		t.Fatalf("payload %d exceeds limit %d", len(out), maxPayloadBytes)
	}
	var res KiroGenerateRequest
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	h := res.ConversationState.History
	t.Logf("input=%d bytes -> output=%d bytes, history items=%d", len(raw), len(out), len(h))
	if len(h) < 50 {
		t.Fatalf("expected most of the history to survive, got %d items", len(h))
	}
	// System prompt priming must remain first.
	if h[0].UserInputMessage == nil || strings.Contains(h[0].UserInputMessage.Content, "truncated") || h[1].AssistantResponseMessage == nil {
		t.Fatalf("system priming pair was not preserved at the head of history")
	}
	// Note: same-role adjacency is pre-existing here (assistant turns holding only
	// tool_use are folded away by sanitizeKiroHistory), so alternation is not asserted.
}

func TestTruncationDropsOldestAndPreservesPriming(t *testing.T) {
	big := strings.Repeat("x", 60*1024)
	msgs := []map[string]any{}
	for i := 0; i < 40; i++ {
		msgs = append(msgs,
			map[string]any{"role": "user", "content": fmt.Sprintf("question %d %s", i, big)},
			map[string]any{"role": "assistant", "content": fmt.Sprintf("answer %d %s", i, big)},
		)
	}
	msgs = append(msgs, map[string]any{"role": "user", "content": "final question"})
	raw, _ := json.Marshal(map[string]any{"model": "claude-opus-5.5", "system": "SYSTEM RULES", "messages": msgs})

	out, _, err := TranslateToKiroRequest(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > maxPayloadBytes {
		t.Fatalf("payload %d exceeds limit %d", len(out), maxPayloadBytes)
	}
	var res KiroGenerateRequest
	_ = json.Unmarshal(out, &res)
	h := res.ConversationState.History
	if h[0].UserInputMessage.Content != "SYSTEM RULES" {
		t.Fatalf("system priming lost: %q", h[0].UserInputMessage.Content)
	}
	if !strings.Contains(h[2].UserInputMessage.Content, "truncated") {
		t.Fatalf("expected truncation marker after priming")
	}
	last := h[len(h)-1].AssistantResponseMessage
	if last == nil || !strings.HasPrefix(last.Content, "answer 39 ") {
		t.Fatalf("most recent turn must be kept")
	}
	if !strings.HasPrefix(h[len(h)-2].UserInputMessage.Content, "question 39 ") {
		t.Fatalf("most recent question must be kept")
	}
	if res.ConversationState.CurrentMessage.UserInputMessage.Content != "final question" {
		t.Fatalf("current message altered")
	}
	// Recent turns must be kept intact (not shrunk).
	if len(last.Content) < len(big) {
		t.Fatalf("recent turn was shrunk")
	}
	assertAlternating(t, h)
}

func TestNoTruncationUnderLimit(t *testing.T) {
	raw := []byte(`{"model":"claude-opus-5.5","system":"S","messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"},{"role":"user","content":"c"}]}`)
	out, _, err := TranslateToKiroRequest(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "truncated") {
		t.Fatalf("small payload must not be truncated")
	}
}

func assertAlternating(t *testing.T, h []KiroHistoryItem) {
	t.Helper()
	for i := 1; i < len(h); i++ {
		if (h[i].UserInputMessage != nil) == (h[i-1].UserInputMessage != nil) {
			t.Fatalf("history[%d] and history[%d] have the same role", i-1, i)
		}
	}
}
