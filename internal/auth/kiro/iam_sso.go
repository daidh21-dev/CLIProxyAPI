package kiro

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type IamSsoSession struct {
	ClientID     string
	ClientSecret string
	CodeVerifier string
	State        string
	Region       string
	StartUrl     string
	RedirectUri  string
	ExpiresAt    time.Time
	mu           sync.Mutex
	consumed     bool
}

var (
	iamSessions   = make(map[string]*IamSsoSession)
	iamSessionsMu sync.RWMutex
)

var defaultScopes = []string{
	"codewhisperer:completions",
	"codewhisperer:analysis",
	"codewhisperer:conversations",
	"codewhisperer:transformations",
	"codewhisperer:taskassist",
}

// StartIamSsoAuth initiates IAM SSO authorization flow.
func (ka *KiroAuth) StartIamSsoAuth(ctx context.Context, startUrl, region string) (sessionID, authorizeUrl string, expiresIn int, err error) {
	if region == "" {
		region = DefaultAwsRegion
	}
	safeRegion := AssertValidAwsRegion(region)

	if startUrl == "" {
		startUrl = DefaultStartURL
	}

	oidcBase := fmt.Sprintf("https://oidc.%s.amazonaws.com", safeRegion)
	redirectUri := "http://127.0.0.1/oauth/callback"

	// 1. Register OIDC Client
	clientID, clientSecret, err := ka.registerOIDCClientForIam(ctx, oidcBase, startUrl, redirectUri)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to register OIDC client: %w", err)
	}

	// 2. Generate PKCE
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)
	state := uuid.New().String()

	// 3. Build authorization URL
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectUri)
	params.Set("scopes", joinScopes())
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	authorizeUrl = fmt.Sprintf("%s/authorize?%s", oidcBase, params.Encode())

	// 4. Save session
	sessionID = uuid.New().String()
	session := &IamSsoSession{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CodeVerifier: codeVerifier,
		State:        state,
		Region:       safeRegion,
		StartUrl:     startUrl,
		RedirectUri:  redirectUri,
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	iamSessionsMu.Lock()
	iamSessions[sessionID] = session
	iamSessionsMu.Unlock()

	go cleanupExpiredIamSessions()

	return sessionID, authorizeUrl, 600, nil
}

// CompleteIamSsoAuth exchanges the authorization code for tokens.
func (ka *KiroAuth) CompleteIamSsoAuth(ctx context.Context, sessionID, callbackUrl string) (*KiroCredentials, error) {
	iamSessionsMu.RLock()
	session, ok := iamSessions[sessionID]
	iamSessionsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("session not found or expired")
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if session.consumed {
		return nil, fmt.Errorf("session already completed")
	}
	if time.Now().After(session.ExpiresAt) {
		session.consumed = true
		iamSessionsMu.Lock()
		delete(iamSessions, sessionID)
		iamSessionsMu.Unlock()
		return nil, fmt.Errorf("session expired")
	}

	parsedURL, err := url.Parse(strings.TrimSpace(callbackUrl))
	if err != nil || !parsedURL.IsAbs() || parsedURL.Opaque != "" ||
		!strings.EqualFold(parsedURL.Scheme, "http") ||
		!strings.EqualFold(parsedURL.Hostname(), "127.0.0.1") ||
		parsedURL.Port() != "" || parsedURL.Path != "/oauth/callback" ||
		parsedURL.User != nil || parsedURL.Fragment != "" {
		return nil, fmt.Errorf("invalid IAM callback URL")
	}
	q := parsedURL.Query()
	state, err := requiredSingleQueryValue(q, "state")
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(state, session.State) {
		return nil, fmt.Errorf("state mismatch error")
	}
	if errorParam, err := optionalSingleQueryValue(q, "error"); err != nil {
		return nil, err
	} else if errorParam != "" {
		session.consumed = true
		delete(iamSessions, sessionID)
		return nil, fmt.Errorf("authorization failed: %s", errorParam)
	}
	code, err := requiredSingleQueryValue(q, "code")
	if err != nil {
		return nil, err
	}
	if len(code) > 8192 {
		return nil, fmt.Errorf("authorization code is too long")
	}

	oidcBase := fmt.Sprintf("https://oidc.%s.amazonaws.com", session.Region)
	accessToken, refreshToken, expiresIn, err := ka.exchangeIamToken(
		ctx,
		oidcBase,
		session.ClientID,
		session.ClientSecret,
		code,
		session.CodeVerifier,
		session.RedirectUri,
	)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	exp := int64(expiresIn)
	if exp <= 0 {
		exp = 3600
	}
	creds := &KiroCredentials{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		AuthMethod:    "idc",
		ClientID:      session.ClientID,
		ClientSecret:  session.ClientSecret,
		Region:        session.Region,
		ExpiresAt:     now.Unix() + exp,
		LastRefreshed: now.Unix(),
	}
	session.consumed = true
	session.CodeVerifier = ""
	session.State = ""
	session.ClientSecret = ""
	iamSessionsMu.Lock()
	delete(iamSessions, sessionID)
	iamSessionsMu.Unlock()
	return creds, nil
}

func (ka *KiroAuth) registerOIDCClientForIam(ctx context.Context, oidcBase, startUrl, redirectUri string) (clientID, clientSecret string, err error) {
	payload := map[string]interface{}{
		"clientName":   DefaultClientName,
		"clientType":   "public",
		"scopes":       defaultScopes,
		"grantTypes":   []string{"authorization_code", "refresh_token"},
		"redirectUris": []string{redirectUri},
		"issuerUrl":    startUrl,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcBase+"/client/register", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}

	return result.ClientID, result.ClientSecret, nil
}

func (ka *KiroAuth) exchangeIamToken(ctx context.Context, oidcBase, clientID, clientSecret, code, codeVerifier, redirectUri string) (accessToken, refreshToken string, expiresIn int, err error) {
	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"grantType":    "authorization_code",
		"redirectUri":  redirectUri,
		"code":         code,
		"codeVerifier": codeVerifier,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcBase+"/token", bytes.NewReader(body))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int    `json:"expiresIn"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, err
	}

	return result.AccessToken, result.RefreshToken, result.ExpiresIn, nil
}

func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func joinScopes() string {
	return strings.Join(defaultScopes, ",")
}

func cleanupExpiredIamSessions() {
	iamSessionsMu.Lock()
	defer iamSessionsMu.Unlock()
	now := time.Now()
	for id, s := range iamSessions {
		if now.After(s.ExpiresAt) {
			delete(iamSessions, id)
		}
	}
}
