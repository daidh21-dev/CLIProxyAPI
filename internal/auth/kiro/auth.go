package kiro

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
)

// KiroCredentials holds Kiro authentication tokens and metadata.
type KiroCredentials struct {
	AccessToken   string `json:"access_token,omitempty"`
	RefreshToken  string `json:"refresh_token,omitempty"`
	ProfileArn    string `json:"profile_arn,omitempty"`
	AuthMethod    string `json:"auth_method,omitempty"` // builder-id, idc, google, github, import, api_key, external_idp
	ClientID      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
	Region        string `json:"region,omitempty"`
	ExpiresAt     int64  `json:"expires_at,omitempty"`
	LastRefreshed int64  `json:"last_refreshed,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	IssuerURL     string `json:"issuer_url,omitempty"`
	Scopes        string `json:"scopes,omitempty"`
	BaseURL       string `json:"base_url,omitempty"`
}

// OidcRegisterClientResponse represents response from /client/register
type OidcRegisterClientResponse struct {
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
}

// DeviceAuthResponse represents response from /device_authorization
type DeviceAuthResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

// TokenResponse represents OAuth token response from AWS OIDC or Kiro Auth service
type TokenResponse struct {
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ProfileArn   string `json:"profileArn,omitempty"`
	ExpiresIn    int64  `json:"expiresIn,omitempty"`
	TokenType    string `json:"tokenType,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// KiroAuth handles Kiro authentication and token operations.
type KiroAuth struct {
	httpClient *http.Client
	mu         sync.RWMutex
}

// NewKiroAuth creates a new Kiro auth instance.
func NewKiroAuth(cfg *config.Config, httpClient *http.Client) *KiroAuth {
	if httpClient != nil {
		return &KiroAuth{httpClient: httpClient}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg != nil {
		client = util.SetProxy(&cfg.SDKConfig, client)
	}
	return &KiroAuth{httpClient: client}
}

// RegisterClient registers an OIDC client with AWS SSO.
func (ka *KiroAuth) RegisterClient(ctx context.Context, region string) (*OidcRegisterClientResponse, error) {
	safeRegion := AssertValidAwsRegion(region)
	endpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com/client/register", safeRegion)

	reqBody := map[string]any{
		"clientName": DefaultClientName,
		"clientType": DefaultClientType,
		"scopes":     DefaultScopes,
		"grantTypes": DefaultGrantTypes,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal register body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register OIDC client: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC client registration failed (%d): %s", resp.StatusCode, string(respBytes))
	}

	var res OidcRegisterClientResponse
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &res, nil
}

// StartDeviceAuthorization initiates OIDC device code authorization.
func (ka *KiroAuth) StartDeviceAuthorization(ctx context.Context, clientID, clientSecret, startURL, region string) (*DeviceAuthResponse, error) {
	safeRegion := AssertValidAwsRegion(region)
	endpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com/device_authorization", safeRegion)

	if startURL == "" {
		startURL = DefaultStartURL
	}

	reqBody := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"startUrl":     startURL,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device auth request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device auth failed (%d): %s", resp.StatusCode, string(respBytes))
	}

	var res DeviceAuthResponse
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	if res.Interval <= 0 {
		res.Interval = 5
	}

	return &res, nil
}

// PollDeviceToken polls AWS OIDC token endpoint until authorized or expired.
func (ka *KiroAuth) PollDeviceToken(ctx context.Context, clientID, clientSecret, deviceCode, region string) (*TokenResponse, error) {
	safeRegion := AssertValidAwsRegion(region)
	endpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com/token", safeRegion)

	reqBody := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"deviceCode":   deviceCode,
		"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal poll body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll token request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read poll response: %w", err)
	}

	var res TokenResponse
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK || res.Error != "" {
		return &res, fmt.Errorf("poll token pending or error: %s (%s)", res.Error, res.ErrorDesc)
	}

	return &res, nil
}

// RefreshToken refreshes an AccessToken using RefreshToken.
func (ka *KiroAuth) RefreshToken(ctx context.Context, creds *KiroCredentials) (*KiroCredentials, error) {
	if creds == nil || creds.RefreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	// 1. Microsoft Enterprise SSO refresh
	if creds.AuthMethod == "microsoft-sso" || (creds.TokenEndpoint != "" && creds.ClientID != "") {
		return ka.RefreshMicrosoftSSOToken(ctx, creds)
	}

	// 2. AWS SSO OIDC refresh (Builder ID or IDC)
	if creds.ClientID != "" && creds.ClientSecret != "" {
		safeRegion := AssertValidAwsRegion(creds.Region)
		endpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com/token", safeRegion)

		reqBody := map[string]string{
			"clientId":     creds.ClientID,
			"clientSecret": creds.ClientSecret,
			"refreshToken": creds.RefreshToken,
			"grantType":    "refresh_token",
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC refresh request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := ka.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("OIDC token refresh failed: %w", err)
		}
		defer resp.Body.Close()

		respBytes, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OIDC token refresh failed (%d): %s", resp.StatusCode, string(respBytes))
		}

		var res TokenResponse
		if err := json.Unmarshal(respBytes, &res); err != nil {
			return nil, fmt.Errorf("failed to parse OIDC token response: %w", err)
		}

		newCreds := *creds
		newCreds.AccessToken = res.AccessToken
		if res.RefreshToken != "" {
			newCreds.RefreshToken = res.RefreshToken
		}
		if res.ProfileArn != "" {
			newCreds.ProfileArn = res.ProfileArn
		}
		if res.ExpiresIn > 0 {
			newCreds.ExpiresAt = time.Now().Unix() + res.ExpiresIn
		}
		newCreds.LastRefreshed = time.Now().Unix()
		return &newCreds, nil
	}

	// 2. Kiro Social Auth refresh (Google / GitHub / Imported)
	endpoint := fmt.Sprintf("%s/refreshToken", KiroAuthService)
	reqBody := map[string]string{
		"refreshToken": creds.RefreshToken,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create Social refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("social token refresh failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("social token refresh failed (%d): %s", resp.StatusCode, string(respBytes))
	}

	var res TokenResponse
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("failed to parse social token response: %w", err)
	}

	newCreds := *creds
	newCreds.AccessToken = res.AccessToken
	if res.RefreshToken != "" {
		newCreds.RefreshToken = res.RefreshToken
	}
	if res.ProfileArn != "" {
		newCreds.ProfileArn = res.ProfileArn
	}
	expiresIn := res.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	newCreds.ExpiresAt = time.Now().Unix() + expiresIn
	newCreds.LastRefreshed = time.Now().Unix()
	return &newCreds, nil
}

// ValidateImportToken validates and exchanges an imported Kiro refresh token.
func (ka *KiroAuth) ValidateImportToken(ctx context.Context, refreshToken string) (*KiroCredentials, error) {
	trimmed := strings.TrimSpace(refreshToken)
	if !strings.HasPrefix(trimmed, "aorAAAAAG") {
		return nil, fmt.Errorf("invalid Kiro import token format (must start with 'aorAAAAAG...')")
	}

	creds := &KiroCredentials{
		RefreshToken: trimmed,
		AuthMethod:   "import",
		Region:       DefaultAwsRegion,
	}

	refreshed, err := ka.RefreshToken(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return refreshed, nil
}

// SaveTokenToFile persists credentials to file.
func SaveTokenToFile(creds *KiroCredentials, filePath string) error {
	if creds == nil || filePath == "" {
		return fmt.Errorf("credentials or filePath is nil")
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	log.Infof("Saved Kiro credentials to %s", filePath)
	return nil
}
