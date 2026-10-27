package kiro

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTranslateReproOrphanToolResult feeds the exact Claude /v1/messages payload
// captured in logs/error-v1-messages-2026-09-30T013928-f0ff3fee.log (268 messages,
// model claude-opus-5.5) through TranslateToKiroRequest and asserts that the
// resulting Kiro conversationState never emits a toolResult whose toolUseId has
// no matching toolUse in the immediately preceding assistant turn.
//
// This is the invariant the AmazonQ upstream enforces (rejecting with
// TOOL_USE_RESULT_MISMATCH / "unexpected tool_use_id ... must have a
// corresponding tool_use block in the previous message").
func TestTranslateReproOrphanToolResult(t *testing.T) {
	fixture := filepath.Join("testdata", "reproduce_orphan_toolresult.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	translated, _, err := TranslateToKiroRequest(raw, "arn:aws:codewhisperer:us-east-1:123:profile")
	if err != nil {
		t.Fatalf("translate failed: %v", err)
	}

	var res KiroGenerateRequest
	if err := json.Unmarshal(translated, &res); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	cs := res.ConversationState

	// Walk history: for every user turn carrying toolResults, the toolUseIds must
	// be covered by toolUses in the assistant turn that immediately precedes it.
	items := cs.History
	violations := 0
	for i, item := range items {
		if item.UserInputMessage == nil || item.UserInputMessage.UserInputMessageContext == nil {
			continue
		}
		results := item.UserInputMessage.UserInputMessageContext.ToolResults
		if len(results) == 0 {
			continue
		}
		prevIDs := map[string]bool{}
		if i > 0 && items[i-1].AssistantResponseMessage != nil {
			for _, tu := range items[i-1].AssistantResponseMessage.ToolUses {
				prevIDs[tu.ToolUseID] = true
			}
		}
		for _, tr := range results {
			if !prevIDs[tr.ToolUseID] {
				violations++
				t.Errorf("history[%d]: toolResult %q has no matching toolUse in preceding assistant turn", i, tr.ToolUseID)
			}
		}
	}

	// Current message toolResults must be covered by the LAST history item's toolUses.
	if cur := cs.CurrentMessage.UserInputMessage.UserInputMessageContext; cur != nil && len(cur.ToolResults) > 0 {
		prevIDs := map[string]bool{}
		if n := len(items); n > 0 && items[n-1].AssistantResponseMessage != nil {
			for _, tu := range items[n-1].AssistantResponseMessage.ToolUses {
				prevIDs[tu.ToolUseID] = true
			}
		}
		for _, tr := range cur.ToolResults {
			if !prevIDs[tr.ToolUseID] {
				violations++
				t.Errorf("currentMessage: toolResult %q has no matching toolUse in last history assistant turn", tr.ToolUseID)
			}
		}
	}

	// Also assert the specific id from the production error is not left orphaned.
	const offending = "toolu_bdrk_01QpbcTQof4Z2BGqFs1a3HUS"
	if strings.Contains(string(translated), offending) {
		// It's fine for it to appear; just make sure it isn't an orphan (covered above).
		t.Logf("offending id %s present in translated payload (expected if paired)", offending)
	}

	if violations > 0 {
		t.Fatalf("found %d orphaned toolResult(s) in translated Kiro payload", violations)
	}
}
