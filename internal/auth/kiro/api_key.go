package kiro

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type KiroApiKeyValidationResult struct {
	ApiKey     string `json:"apiKey"`
	Region     string `json:"region"`
	AuthMethod string `json:"authMethod"`
}

// ValidateKiroApiKey validates an API-key credential through the Amazon Q model catalog.
func ValidateKiroApiKey(apiKey, region string) (*KiroApiKeyValidationResult, error) {
	trimmed := strings.TrimSpace(apiKey)
	if trimmed == "" {
		return nil, fmt.Errorf("API key is required")
	}

	if region == "" {
		region = "us-east-1"
	}

	endpoint := fmt.Sprintf("https://q.%s.amazonaws.com/ListAvailableModels?origin=AI_EDITOR", url.QueryEscape(region))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build API key request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+trimmed)
	req.Header.Set("TokenType", "API_KEY")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AWS-SDK-JS/3.0.0 kiro-ide/1.0.0")
	req.Header.Set("X-Amz-User-Agent", "aws-sdk-js/3.0.0 kiro-ide/1.0.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API key request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API key validation failed with status %d", resp.StatusCode)
	}

	var data struct {
		Models []any `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode model catalog response: %w", err)
	}

	if len(data.Models) == 0 {
		return nil, fmt.Errorf("API key returned no available models")
	}

	return &KiroApiKeyValidationResult{
		ApiKey:     trimmed,
		Region:     region,
		AuthMethod: "api_key",
	}, nil
}
