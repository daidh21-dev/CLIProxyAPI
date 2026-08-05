// Package kiro translates standard OpenAI/Claude requests into Kiro / CodeWhisperer conversation payload formats.
package kiro

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// KiroUserMessage represents a user message in Kiro payload.
type KiroUserMessage struct {
	Content string `json:"content"`
	ModelID string `json:"modelId,omitempty"`
	Origin  string `json:"origin,omitempty"`
}

// KiroAssistantMessage represents an assistant message in Kiro payload.
type KiroAssistantMessage struct {
	Content string `json:"content"`
}

// KiroHistoryItem represents a turn in Kiro history.
type KiroHistoryItem struct {
	UserInputMessage         *KiroUserMessage      `json:"userInputMessage,omitempty"`
	AssistantResponseMessage *KiroAssistantMessage `json:"assistantResponseMessage,omitempty"`
}

// KiroCurrentMessage wraps the current user input message.
type KiroCurrentMessage struct {
	UserInputMessage KiroUserMessage `json:"userInputMessage"`
}

// KiroConversationState represents the conversationState field in GenerateAssistantResponse.
type KiroConversationState struct {
	ChatTriggerType string             `json:"chatTriggerType"`
	ConversationID  string             `json:"conversationId"`
	CurrentMessage  KiroCurrentMessage `json:"currentMessage"`
	History         []KiroHistoryItem  `json:"history,omitempty"`
}

// KiroInferenceConfig represents optional generation controls accepted by Kiro.
type KiroInferenceConfig struct {
	MaxTokens   int      `json:"maxTokens,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"topP,omitempty"`
}

// KiroGenerateRequest represents the top-level payload for GenerateAssistantResponse.
type KiroGenerateRequest struct {
	ConversationState KiroConversationState `json:"conversationState"`
	ProfileArn        string                `json:"profileArn,omitempty"`
	InferenceConfig   *KiroInferenceConfig  `json:"inferenceConfig,omitempty"`
}

// OpenAIInputMessage represents standard OpenAI message structure.
type OpenAIInputMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// OpenAIRequest represents standard OpenAI chat completion request.
type OpenAIRequest struct {
	Model       string               `json:"model"`
	Messages    []OpenAIInputMessage `json:"messages"`
	MaxTokens   int                  `json:"max_tokens,omitempty"`
	Temperature *float64             `json:"temperature,omitempty"`
	TopP        *float64             `json:"top_p,omitempty"`
}

// TranslateToKiroRequest converts an OpenAI/Claude JSON payload into Kiro's GenerateAssistantResponse format.
func TranslateToKiroRequest(rawBody []byte, profileArn string) ([]byte, string, error) {
	var req OpenAIRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal OpenAI request: %w", err)
	}

	cleanModel := CleanKiroModelID(req.Model)

	var history []KiroHistoryItem
	var lastUserContent string
	var systemPrompt strings.Builder

	for _, msg := range req.Messages {
		contentStr := extractContentString(msg.Content)

		switch strings.ToLower(msg.Role) {
		case "system":
			if systemPrompt.Len() > 0 {
				systemPrompt.WriteString("\n")
			}
			systemPrompt.WriteString(contentStr)
		case "user":
			if lastUserContent != "" {
				history = append(history, KiroHistoryItem{
					UserInputMessage: &KiroUserMessage{Content: lastUserContent},
				})
			}
			lastUserContent = contentStr
		case "assistant":
			history = append(history, KiroHistoryItem{
				AssistantResponseMessage: &KiroAssistantMessage{Content: contentStr},
			})
		}
	}

	// Prepend system prompt to current user message if system prompt exists
	currentUserContent := lastUserContent
	if systemPrompt.Len() > 0 {
		if currentUserContent != "" {
			currentUserContent = fmt.Sprintf("System Instructions:\n%s\n\nUser Request:\n%s", systemPrompt.String(), currentUserContent)
		} else {
			currentUserContent = systemPrompt.String()
		}
	}

	if currentUserContent == "" {
		currentUserContent = "Hello"
	}

	kiroReq := KiroGenerateRequest{
		ConversationState: KiroConversationState{
			ChatTriggerType: "MANUAL",
			ConversationID:  uuid.New().String(),
			CurrentMessage: KiroCurrentMessage{
				UserInputMessage: KiroUserMessage{
					Content: currentUserContent,
					ModelID: cleanModel,
					Origin:  "AI_EDITOR",
				},
			},
			History: history,
		},
		ProfileArn: profileArn,
		InferenceConfig: func() *KiroInferenceConfig {
			if req.MaxTokens == 0 && req.Temperature == nil && req.TopP == nil {
				return nil
			}
			return &KiroInferenceConfig{
				MaxTokens:   req.MaxTokens,
				Temperature: req.Temperature,
				TopP:        req.TopP,
			}
		}(),
	}

	outBytes, err := json.Marshal(kiroReq)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal Kiro request: %w", err)
	}

	return outBytes, cleanModel, nil
}

// CleanKiroModelID strips provider prefix (kr/, kiro/) and suffix variants (-thinking, -agentic).
func CleanKiroModelID(model string) string {
	model = strings.TrimSpace(model)
	model = strings.TrimPrefix(model, "kr/")
	model = strings.TrimPrefix(model, "kiro/")
	model = strings.TrimSuffix(model, "-thinking-agentic")
	model = strings.TrimSuffix(model, "-thinking")
	model = strings.TrimSuffix(model, "-agentic")
	switch strings.ToLower(model) {
	case "", "kiro", "kiro-auto", "auto":
		return "claude-sonnet-4.5"
	case "claude-sonnet-4-20250514", "claude-sonnet-4-0", "claude-sonnet-4.0":
		return "claude-sonnet-4"
	case "claude-3-5-sonnet", "claude-3.5-sonnet", "claude-sonnet-4-5", "claude-3-7-sonnet", "claude-3.7-sonnet":
		return "claude-sonnet-4.5"
	case "claude-haiku-4.5", "claude-haiku-4-5":
		return "claude-haiku-4.5"
	case "claude-opus-4.5", "claude-opus-4-5":
		return "claude-opus-4.5"
	case "claude-opus-4.6", "claude-opus-4-6":
		return "claude-opus-4.6"
	case "claude-opus-4.7", "claude-opus-4-7":
		return "claude-opus-4.7"
	case "claude-opus-4.8", "claude-opus-4-8":
		return "claude-opus-4.8"
	case "claude-sonnet-4.6", "claude-sonnet-4-6":
		return "claude-sonnet-4.6"
	case "deepseek-v3.2", "deepseek-3.2", "deepseek-3-2":
		return "deepseek-3.2"
	case "minimax-m2.5", "minimax-m2-5":
		return "minimax-m2.5"
	case "minimax-m2.1", "minimax-m2-1":
		return "minimax-m2.1"
	case "gpt-5.6-sol", "gpt-5-6-sol":
		return "gpt-5.6-sol"
	case "gpt-5.6-terra", "gpt-5-6-terra":
		return "gpt-5.6-terra"
	case "gpt-5.6-luna", "gpt-5-6-luna":
		return "gpt-5.6-luna"
	}
	return model
}

func extractContentString(content any) string {
	if content == nil {
		return ""
	}
	switch v := content.(type) {
	case string:
		return v
	case []any:
		var sb strings.Builder
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if text, ok := m["text"].(string); ok {
					sb.WriteString(text)
				}
			}
		}
		return sb.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}
