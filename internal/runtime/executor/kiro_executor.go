package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	kiroeventstream "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	kirotranslator "github.com/router-for-me/CLIProxyAPI/v7/internal/translator/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

const (
	KiroUserAgent       = "aws-sdk-js/3.0.0 ua/2.1 os/windows#10.0.26200 lang/js md/nodejs#22.21.1 api/codewhispererruntime#1.0.0 m/N,E KiroIDE-0.10.32-kiro-anonymous"
	KiroAmzUserAgent    = "aws-sdk-js/3.0.0 KiroIDE-0.10.32-kiro-anonymous"
	KiroCodeWhispererTarget = "AmazonCodeWhispererStreamingService.GenerateAssistantResponse"
)

var kiroBaseURLs = []string{
	"https://runtime.us-east-1.kiro.dev/generateAssistantResponse",
	"https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse",
	"https://q.us-east-1.amazonaws.com/generateAssistantResponse",
}

// KiroExecutor handles requests for Kiro AI (AWS CodeWhisperer/Amazon Q).
type KiroExecutor struct {
	cfg        *config.Config
	httpClient *http.Client
	authSvc    *kiroauth.KiroAuth
}

// NewKiroExecutor creates a new KiroExecutor instance.
func NewKiroExecutor(cfg *config.Config) *KiroExecutor {
	client := &http.Client{}
	if cfg != nil {
		client = util.SetProxy(&cfg.SDKConfig, client)
	}
	return &KiroExecutor{
		cfg:        cfg,
		httpClient: client,
		authSvc:    kiroauth.NewKiroAuth(cfg, client),
	}
}

// Identifier returns the unique executor identifier.
func (e *KiroExecutor) Identifier() string {
	return "kiro"
}

// PrepareRequest prepares the HTTP request with Kiro headers.
func (e *KiroExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	return nil
}

// BuildHeaders constructs the required headers for Kiro API call.
func (e *KiroExecutor) BuildHeaders(targetURL string, accessToken string, authMethod string) http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("Accept", "application/vnd.amazon.eventstream")
	headers.Set("User-Agent", KiroUserAgent)
	headers.Set("X-Amz-User-Agent", KiroAmzUserAgent)
	headers.Set("x-amzn-kiro-agent-mode", "vibe")
	headers.Set("x-amzn-codewhisperer-optout", "true")
	headers.Set("Amz-Sdk-Request", "attempt=1; max=3")
	headers.Set("Amz-Sdk-Invocation-Id", uuid.New().String())

	if strings.Contains(targetURL, "://codewhisperer.") || strings.Contains(targetURL, "://q.") {
		headers.Set("X-Amz-Target", KiroCodeWhispererTarget)
	}

	if accessToken != "" {
		headers.Set("Authorization", "Bearer "+accessToken)
	}

	switch authMethod {
	case "api_key":
		headers.Set("TokenType", "API_KEY")
		headers.Set("tokentype", "API_KEY")
	case "external_idp":
		headers.Set("TokenType", "EXTERNAL_IDP")
	}

	return headers
}

// GetOrderedBaseURLs orders the base URLs based on auth method.
func (e *KiroExecutor) GetOrderedBaseURLs(authMethod string, region string) []string {
	safeRegion := kiroauth.AssertValidAwsRegion(region)

	isCodeWhispererSurface := authMethod == "api_key" || authMethod == "external_idp" || authMethod == "idc"
	if !isCodeWhispererSurface {
		return kiroBaseURLs
	}

	var regionalized []string
	for _, u := range kiroBaseURLs {
		if safeRegion != "us-east-1" && strings.Contains(u, "amazonaws.com") {
			u = strings.Replace(u, ".us-east-1.amazonaws.com", "."+safeRegion+".amazonaws.com", 1)
		}
		regionalized = append(regionalized, u)
	}

	if authMethod == "api_key" {
		var qURLs, otherURLs []string
		for _, u := range regionalized {
			if strings.Contains(u, "://q.") {
				qURLs = append(qURLs, u)
			} else {
				otherURLs = append(otherURLs, u)
			}
		}
		return append(qURLs, otherURLs...)
	}

	return regionalized
}

// ExecuteKiroStream sends the translated request to Kiro and streams SSE back to the client.
func (e *KiroExecutor) ExecuteKiroStream(ctx context.Context, model string, reqBody []byte, accessToken string, profileArn string, authMethod string, region string, w http.ResponseWriter) error {
	// 1. Translate request payload to Kiro payload format
	kiroPayload, cleanModel, err := kirotranslator.TranslateToKiroRequest(reqBody, profileArn)
	if err != nil {
		return fmt.Errorf("kiro translation failed: %w", err)
	}
	log.Debugf("Kiro request translated for model %s: %s", cleanModel, string(kiroPayload))

	// 2. Select ordered URLs
	urls := e.GetOrderedBaseURLs(authMethod, region)

	var lastErr error
	var resp *http.Response

	for _, targetURL := range urls {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(kiroPayload))
		if err != nil {
			lastErr = err
			continue
		}

		httpReq.Header = e.BuildHeaders(targetURL, accessToken, authMethod)

		log.Infof("Sending request to Kiro endpoint: %s", targetURL)
		resp, err = e.httpClient.Do(httpReq)
		if err != nil {
			lastErr = err
			log.Warnf("Kiro request to %s failed: %v", targetURL, err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			break
		}

		respBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastErr = fmt.Errorf("Kiro API %s returned status %d: %s", targetURL, resp.StatusCode, string(respBytes))
		log.Warnf("%v", lastErr)
	}

	if resp == nil || resp.StatusCode != http.StatusOK {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("failed to execute request across all Kiro endpoints")
	}
	defer resp.Body.Close()

	// Set SSE response headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)

	// 3. Read and decode AWS EventStream frames
	messageID := "chatcmpl-" + uuid.New().String()
	created := time.Now().Unix()

	for {
		frame, err := kiroeventstream.ReadEventStreamFrame(resp.Body)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Debugf("EventStream decode finished or stopped: %v", err)
			break
		}

		eventType := frame.EventType()
		content, reasoning, parseErr := frame.ParseAssistantEvent()
		if parseErr != nil {
			continue
		}

		if content != "" || reasoning != "" {
			chunk := map[string]any{
				"id":      messageID,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []map[string]any{
					{
						"index": 0,
						"delta": map[string]any{
							"content":           content,
							"reasoning_content": reasoning,
						},
						"finish_reason": nil,
					},
				},
			}
			chunkBytes, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", string(chunkBytes))
			if ok {
				flusher.Flush()
			}
		}

		if eventType == "messageStopEvent" {
			stopChunk := map[string]any{
				"id":      messageID,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []map[string]any{
					{
						"index":         0,
						"delta":         map[string]any{},
						"finish_reason": "stop",
					},
				},
			}
			stopBytes, _ := json.Marshal(stopChunk)
			fmt.Fprintf(w, "data: %s\n\n", string(stopBytes))
			fmt.Fprintf(w, "data: [DONE]\n\n")
			if ok {
				flusher.Flush()
			}
			break
		}
	}

	return nil
}

func (e *KiroExecutor) executeRequest(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request) (*http.Response, http.Header, string, string, error) {
	if e == nil {
		return nil, nil, "", "", fmt.Errorf("kiro executor: executor is nil")
	}
	if auth == nil {
		return nil, nil, "", "", fmt.Errorf("kiro executor: auth is nil")
	}
	creds := kiroauth.CredentialsFromAuth(auth)
	if creds == nil {
		return nil, nil, "", "", fmt.Errorf("kiro executor: missing credentials")
	}
	profileArn := strings.TrimSpace(creds.ProfileArn)
	if profileArn == "" {
		if resolved, errResolve := e.authSvc.ResolveProfileArn(ctx, creds); errResolve == nil {
			profileArn = strings.TrimSpace(resolved)
		}
	}
	payload, cleanModel, err := kirotranslator.TranslateToKiroRequest(req.Payload, profileArn)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("kiro translation failed: %w", err)
	}
	urls := e.GetOrderedBaseURLs(strings.ToLower(strings.TrimSpace(creds.AuthMethod)), creds.Region)
	if len(urls) == 0 {
		return nil, nil, "", "", fmt.Errorf("kiro executor: no upstream endpoints available")
	}

	client := e.httpClient
	if auth.ProxyURL != "" {
		client = helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	}
	if client == nil {
		client = http.DefaultClient
	}

	var lastErr error
	for _, targetURL := range urls {
		httpReq, errReq := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
		if errReq != nil {
			lastErr = errReq
			continue
		}
		httpReq.Header = e.BuildHeaders(targetURL, strings.TrimSpace(creds.AccessToken), strings.ToLower(strings.TrimSpace(creds.AuthMethod)))
		resp, errReq := client.Do(httpReq)
		if errReq != nil {
			lastErr = errReq
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp, resp.Header.Clone(), cleanModel, targetURL, nil
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		lastErr = fmt.Errorf("kiro api %s returned status %d: %s", targetURL, resp.StatusCode, string(body))
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("kiro executor: request failed")
	}
	return nil, nil, "", "", lastErr
}

func (e *KiroExecutor) resolveBaseURL(auth *cliproxyauth.Auth, creds *kiroauth.KiroCredentials) string {
	if creds != nil && strings.TrimSpace(creds.BaseURL) != "" {
		return strings.TrimSpace(creds.BaseURL)
	}
	if auth != nil && auth.Attributes != nil {
		if u := strings.TrimSpace(auth.Attributes["base_url"]); u != "" {
			return u
		}
	}
	if envURL := strings.TrimSpace(os.Getenv("KIRO_GO_URL")); envURL != "" {
		return envURL
	}
	return ""
}

func (e *KiroExecutor) executeKiroGo(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, baseURL string) (cliproxyexecutor.Response, error) {
	var resp cliproxyexecutor.Response
	targetURL := strings.TrimSuffix(baseURL, "/") + "/v1/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(req.Payload))
	if err != nil {
		return resp, fmt.Errorf("kiro-go request create failed: %w", err)
	}

	creds := kiroauth.CredentialsFromAuth(auth)
	token := ""
	authMethod := ""
	if creds != nil {
		token = strings.TrimSpace(creds.AccessToken)
		authMethod = strings.ToLower(strings.TrimSpace(creds.AuthMethod))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	if authMethod == "api_key" {
		httpReq.Header.Set("tokentype", "API_KEY")
	}

	client := e.httpClient
	if auth != nil && auth.ProxyURL != "" {
		client = helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	}
	if client == nil {
		client = http.DefaultClient
	}

	res, err := client.Do(httpReq)
	if err != nil {
		return resp, fmt.Errorf("kiro-go request failed: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return resp, fmt.Errorf("kiro-go read response failed: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("kiro-go status %d: %s", res.StatusCode, string(body))
	}

	resp.Headers = res.Header.Clone()
	resp.Payload = body
	return resp, nil
}

func (e *KiroExecutor) executeKiroGoStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, baseURL string) (*cliproxyexecutor.StreamResult, error) {
	targetURL := strings.TrimSuffix(baseURL, "/") + "/v1/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(req.Payload))
	if err != nil {
		return nil, fmt.Errorf("kiro-go request create failed: %w", err)
	}

	creds := kiroauth.CredentialsFromAuth(auth)
	token := ""
	authMethod := ""
	if creds != nil {
		token = strings.TrimSpace(creds.AccessToken)
		authMethod = strings.ToLower(strings.TrimSpace(creds.AuthMethod))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	if authMethod == "api_key" {
		httpReq.Header.Set("tokentype", "API_KEY")
	}

	client := e.httpClient
	if auth != nil && auth.ProxyURL != "" {
		client = helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	}
	if client == nil {
		client = http.DefaultClient
	}

	res, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("kiro-go stream request failed: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return nil, fmt.Errorf("kiro-go status %d: %s", res.StatusCode, string(body))
	}

	headers := res.Header.Clone()
	out := make(chan cliproxyexecutor.StreamChunk, 16)

	go func() {
		defer close(out)
		defer res.Body.Close()

		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				dataStr := strings.TrimPrefix(line, "data: ")
				if dataStr == "[DONE]" {
					return
				}
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: []byte(dataStr)}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return &cliproxyexecutor.StreamResult{Headers: headers, Chunks: out}, nil
}

func (e *KiroExecutor) parseEventStream(resp *http.Response, model string) ([]byte, []byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil, fmt.Errorf("kiro executor: response body is nil")
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("kiro executor: close response body error: %v", errClose)
		}
	}()
	var content strings.Builder
	var reasoning strings.Builder
	for {
		frame, errFrame := kiroeventstream.ReadEventStreamFrame(resp.Body)
		if errFrame != nil {
			if errFrame == io.EOF {
				break
			}
			if errors.Is(errFrame, kiroeventstream.ErrUnexpectedEOF) {
				break
			}
			return nil, nil, errFrame
		}
		text, thought, errParse := frame.ParseAssistantEvent()
		if errParse != nil {
			return nil, nil, errParse
		}
		if text != "" {
			content.WriteString(text)
		}
		if thought != "" {
			reasoning.WriteString(thought)
		}
		if frame.EventType() == "messageStopEvent" {
			break
		}
	}
	return []byte(content.String()), []byte(reasoning.String()), nil
}

// Execute implements ProviderExecutor interface.
func (e *KiroExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	creds := kiroauth.CredentialsFromAuth(auth)
	if baseURL := e.resolveBaseURL(auth, creds); baseURL != "" {
		return e.executeKiroGo(ctx, auth, req, opts, baseURL)
	}
	respUpstream, headers, _, _, errReq := e.executeRequest(ctx, auth, req)
	if errReq != nil {
		return resp, errReq
	}
	if respUpstream == nil {
		return resp, fmt.Errorf("kiro executor: missing upstream response")
	}
	content, reasoning, errParse := e.parseEventStream(respUpstream, req.Model)
	if errParse != nil {
		return resp, errParse
	}
	payloadOut := map[string]any{
		"id":      "chatcmpl-" + uuid.New().String(),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   req.Model,
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role":              "assistant",
				"content":           string(content),
				"reasoning_content": string(reasoning),
			},
			"finish_reason": "stop",
		}},
	}
	if headers != nil {
		resp.Headers = headers
	}
	bodyOut, _ := json.Marshal(payloadOut)
	resp.Payload = bodyOut
	return resp, nil
}

// ExecuteStream implements ProviderExecutor interface.
func (e *KiroExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (res *cliproxyexecutor.StreamResult, err error) {
	creds := kiroauth.CredentialsFromAuth(auth)
	if baseURL := e.resolveBaseURL(auth, creds); baseURL != "" {
		return e.executeKiroGoStream(ctx, auth, req, opts, baseURL)
	}
	respUpstream, headers, _, _, errReq := e.executeRequest(ctx, auth, req)
	if errReq != nil {
		return nil, errReq
	}
	if respUpstream == nil {
		return nil, fmt.Errorf("kiro executor: missing upstream response")
	}
	if headers == nil {
		headers = make(http.Header)
	}
	out := make(chan cliproxyexecutor.StreamChunk, 16)
	go func() {
		defer close(out)
		defer func() {
			if errClose := respUpstream.Body.Close(); errClose != nil {
				log.Errorf("kiro executor: close response body error: %v", errClose)
			}
		}()
		for {
			frame, errFrame := kiroeventstream.ReadEventStreamFrame(respUpstream.Body)
			if errFrame != nil {
				if errFrame == io.EOF || errors.Is(errFrame, kiroeventstream.ErrUnexpectedEOF) {
					return
				}
				select {
				case out <- cliproxyexecutor.StreamChunk{Err: errFrame}:
				case <-ctx.Done():
				}
				return
			}
			text, thought, errParse := frame.ParseAssistantEvent()
			if errParse != nil {
				select {
				case out <- cliproxyexecutor.StreamChunk{Err: errParse}:
				case <-ctx.Done():
				}
				return
			}
			if text != "" || thought != "" {
				chunk := map[string]any{
					"id":      "chatcmpl-" + uuid.New().String(),
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   req.Model,
					"choices": []map[string]any{{
						"index": 0,
						"delta": map[string]any{
							"content":           text,
							"reasoning_content": thought,
						},
						"finish_reason": nil,
					}},
				}
				body, _ := json.Marshal(chunk)
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: body}:
				case <-ctx.Done():
					return
				}
			}
			if frame.EventType() == "messageStopEvent" {
				stopChunk := map[string]any{
					"id":      "chatcmpl-" + uuid.New().String(),
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   req.Model,
					"choices": []map[string]any{{
						"index":         0,
						"delta":         map[string]any{},
						"finish_reason": "stop",
					}},
				}
				body, _ := json.Marshal(stopChunk)
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: body}:
				case <-ctx.Done():
				}
				return
			}
		}
	}()
	headers.Set("Content-Type", "text/event-stream")
	return &cliproxyexecutor.StreamResult{Headers: headers, Chunks: out}, nil
}

// Refresh implements ProviderExecutor interface.
func (e *KiroExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, nil
	}
	creds := kiroauth.CredentialsFromAuth(auth)
	if creds == nil {
		return auth.Clone(), nil
	}
	if strings.EqualFold(strings.TrimSpace(creds.AuthMethod), "api_key") {
		return auth.Clone(), nil
	}
	refreshed, err := e.authSvc.RefreshToken(ctx, creds)
	if err != nil {
		return nil, err
	}
	if refreshed == nil {
		return auth.Clone(), nil
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = creds.RefreshToken
	}
	if refreshed.ProfileArn == "" {
		refreshed.ProfileArn = creds.ProfileArn
	}
	if refreshed.ExpiresAt == 0 && creds.ExpiresAt > 0 {
		refreshed.ExpiresAt = creds.ExpiresAt
	}
	if refreshed.LastRefreshed == 0 {
		refreshed.LastRefreshed = time.Now().Unix()
	}
	updated := auth.Clone()
	kiroauth.ApplyCredentialsToAuth(updated, refreshed)
	kiroauth.SetRefreshFingerprints(updated, refreshed.RefreshToken, creds.RefreshToken)
	return updated, nil
}

// CountTokens implements ProviderExecutor interface.
func (e *KiroExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	return resp, fmt.Errorf("CountTokens not supported for Kiro")
}

// HttpRequest implements ProviderExecutor interface.
func (e *KiroExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("kiro executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	client := e.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(httpReq)
}
