package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	kiroeventstream "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/kiro"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tiktoken-go/tokenizer"
)

// Kiro's event stream does not report token usage. Without usage, Claude Code
// believes its context is empty, never auto-compacts, and the request keeps
// growing until the proxy has to drop history. These helpers estimate usage
// locally (O200kBase) from the client's original request and the response.

var (
	kiroOutputTokenizerOnce sync.Once
	kiroOutputTokenizer     tokenizer.Codec
	kiroOutputTokenizerErr  error
)

// kiroEstimateInputTokens estimates prompt tokens for the client request
// (pre-truncation, i.e. what the client believes it sent).
func kiroEstimateInputTokens(payload []byte) int {
	count, err := helps.CountClaudeInputTokens(payload)
	if err != nil {
		log.Debugf("kiro executor: estimate input tokens: %v", err)
		return 0
	}
	return int(count)
}

// kiroEstimateTextTokens estimates tokens for generated output text.
func kiroEstimateTextTokens(parts ...string) int {
	kiroOutputTokenizerOnce.Do(func() {
		kiroOutputTokenizer, kiroOutputTokenizerErr = tokenizer.Get(tokenizer.O200kBase)
	})
	if kiroOutputTokenizerErr != nil || kiroOutputTokenizer == nil {
		return 0
	}
	text := strings.Join(parts, "\n")
	if strings.TrimSpace(text) == "" {
		return 0
	}
	n, err := kiroOutputTokenizer.Count(text)
	if err != nil {
		return 0
	}
	return n
}

func kiroToolUsesText(toolUses []kiroeventstream.ToolUse) string {
	if len(toolUses) == 0 {
		return ""
	}
	var b strings.Builder
	for _, tu := range toolUses {
		b.WriteString(tu.Name)
		b.WriteByte('\n')
		if raw, err := json.Marshal(tu.Input); err == nil {
			b.Write(raw)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// CountTokens implements ProviderExecutor interface using a local estimate.
func (e *KiroExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	count, err := helps.CountClaudeInputTokens(req.Payload)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("kiro executor: token counting failed: %w", err)
	}
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	usageJSON := []byte(fmt.Sprintf(`{"input_tokens":%d}`, count))
	out := sdktranslator.TranslateTokenCount(ctx, sdktranslator.FromString("claude"), responseFormat, count, usageJSON)
	return cliproxyexecutor.Response{Payload: out}, nil
}
