package kiro

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ImportFromSsoToken exchanges an AWS SSO Bearer token for Kiro Credentials.
func (ka *KiroAuth) ImportFromSsoToken(ctx context.Context, bearerToken, region string) (*KiroCredentials, error) {
	if region == "" {
		region = DefaultAwsRegion
	}
	safeRegion := AssertValidAwsRegion(region)

	oidcBase := fmt.Sprintf("https://oidc.%s.amazonaws.com", safeRegion)
	portalBase := "https://portal.sso.us-east-1.amazonaws.com"
	startUrl := DefaultStartURL

	// 1. Register device client
	clientID, clientSecret, err := ka.registerDeviceClientForSso(ctx, oidcBase, startUrl)
	if err != nil {
		return nil, fmt.Errorf("client registration failed: %w", err)
	}

	// 2. Start device authorization
	deviceCode, userCode, interval, err := ka.startDeviceAuthForSso(ctx, oidcBase, clientID, clientSecret, startUrl)
	if err != nil {
		return nil, fmt.Errorf("device auth failed: %w", err)
	}

	// 3. Verify Bearer token
	if err := ka.verifyBearerToken(ctx, portalBase, bearerToken); err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// 4. Get device session token
	deviceSessionToken, err := ka.getDeviceSessionToken(ctx, portalBase, bearerToken)
	if err != nil {
		return nil, fmt.Errorf("get device session failed: %w", err)
	}

	// 5. Accept user code
	deviceContext, err := ka.acceptUserCode(ctx, oidcBase, userCode, deviceSessionToken)
	if err != nil {
		return nil, fmt.Errorf("accept user code failed: %w", err)
	}

	// 6. Approve auth
	if deviceContext != nil {
		if err := ka.approveAuth(ctx, oidcBase, deviceContext, deviceSessionToken); err != nil {
			return nil, fmt.Errorf("approve auth failed: %w", err)
		}
	}

	// 7. Poll for token
	accessToken, refreshToken, expiresIn, err := ka.pollForSsoToken(ctx, oidcBase, clientID, clientSecret, deviceCode, interval)
	if err != nil {
		return nil, fmt.Errorf("poll token failed: %w", err)
	}

	now := time.Now()
	exp := int64(expiresIn)
	if exp <= 0 {
		exp = 3600
	}

	return &KiroCredentials{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		AuthMethod:    "builder-id",
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Region:        safeRegion,
		ExpiresAt:     now.Unix() + exp,
		LastRefreshed: now.Unix(),
	}, nil
}

func (ka *KiroAuth) registerDeviceClientForSso(ctx context.Context, oidcBase, startUrl string) (clientID, clientSecret string, err error) {
	payload := map[string]interface{}{
		"clientName": DefaultClientName,
		"clientType": "public",
		"scopes":     defaultScopes,
		"grantTypes": []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		"issuerUrl":  startUrl,
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

func (ka *KiroAuth) startDeviceAuthForSso(ctx context.Context, oidcBase, clientID, clientSecret, startUrl string) (deviceCode, userCode string, interval int, err error) {
	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"startUrl":     startUrl,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcBase+"/device_authorization", bytes.NewReader(body))
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
		DeviceCode string `json:"deviceCode"`
		UserCode   string `json:"userCode"`
		Interval   int    `json:"interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, err
	}

	if result.Interval <= 0 {
		result.Interval = 1
	}

	return result.DeviceCode, result.UserCode, result.Interval, nil
}

func (ka *KiroAuth) verifyBearerToken(ctx context.Context, portalBase, bearerToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, portalBase+"/token/device/session", nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-amz-sso_authn", strings.TrimSpace(bearerToken))

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (ka *KiroAuth) getDeviceSessionToken(ctx context.Context, portalBase, bearerToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, portalBase+"/token/device/session", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-amz-sso_authn", strings.TrimSpace(bearerToken))

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Token, nil
}

type deviceContextInfo struct {
	UserCode string `json:"userCode"`
}

func (ka *KiroAuth) acceptUserCode(ctx context.Context, oidcBase, userCode, deviceSessionToken string) (*deviceContextInfo, error) {
	payload := map[string]string{
		"userCode": userCode,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcBase+"/device_authorization/associate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-amz-sso_authn", deviceSessionToken)

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result deviceContextInfo
	json.NewDecoder(resp.Body).Decode(&result)
	return &result, nil
}

func (ka *KiroAuth) approveAuth(ctx context.Context, oidcBase string, deviceContext *deviceContextInfo, deviceSessionToken string) error {
	payload := map[string]interface{}{
		"userCode": deviceContext.UserCode,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcBase+"/device_authorization/approve", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-amz-sso_authn", deviceSessionToken)

	resp, err := ka.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (ka *KiroAuth) pollForSsoToken(ctx context.Context, oidcBase, clientID, clientSecret, deviceCode string, interval int) (accessToken, refreshToken string, expiresIn int, err error) {
	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"deviceCode":   deviceCode,
		"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
	}

	body, _ := json.Marshal(payload)

	for i := 0; i < 5; i++ {
		time.Sleep(time.Duration(interval) * time.Second)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcBase+"/token", bytes.NewReader(body))
		if err != nil {
			return "", "", 0, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := ka.httpClient.Do(req)
		if err != nil {
			continue
		}

		respBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var result struct {
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
				ExpiresIn    int    `json:"expiresIn"`
			}
			if err := json.Unmarshal(respBytes, &result); err == nil && result.AccessToken != "" {
				return result.AccessToken, result.RefreshToken, result.ExpiresIn, nil
			}
		}
	}

	return "", "", 0, fmt.Errorf("timeout waiting for SSO token")
}
