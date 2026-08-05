package kiro

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	MicrosoftSSOAuthMethod = "external_idp"
	MicrosoftSSOProvider   = "AzureAD"

	microsoftPortalSignInURL   = "https://app.kiro.dev/signin"
	microsoftLoopbackBaseURL   = "http://localhost:3128"
	microsoftPortalCallback    = "/signin/callback"
	microsoftOAuthCallback     = "/oauth/callback"
	microsoftSSORedirectSource = "KiroIDE"
	microsoftSSOSessionTTL     = 10 * time.Minute
	microsoftSSOMaxSessions    = 64
	microsoftSSOMaxCallbackLen = 16 << 10
	microsoftSSOMaxResponse    = 1 << 20
)

const KiroSocialDefaultLoopbackPath = "/oauth/callback"

type microsoftSSOStage uint8

const (
	microsoftSSOWaitingForPortal microsoftSSOStage = iota + 1
	microsoftSSOWaitingForProvider
)

type microsoftProviderLeg struct {
	State                 string
	CodeVerifier          string
	IssuerURL             string
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	Scopes                string
}

type microsoftSSOSession struct {
	ID           string
	Provider     string
	PortalState  string
	CodeVerifier string
	RedirectURI  string
	ExpiresAt    time.Time
	timer        *time.Timer
	mu           sync.Mutex
	canceled     atomic.Bool
	stage        microsoftSSOStage
	providerLeg  *microsoftProviderLeg
}

type MicrosoftSSOResult struct {
	AccessToken   string
	RefreshToken  string
	ProfileArn    string
	ClientID      string
	TokenEndpoint string
	IssuerURL     string
	Scopes        string
	Email         string
	UserID        string
	ExpiresAt     int64
}

type MicrosoftSSOProgress struct {
	AuthorizationURL string
	Result           *MicrosoftSSOResult
}

var (
	microsoftSSOSessions   = make(map[string]*microsoftSSOSession)
	microsoftSSOSessionsMu sync.Mutex
)

// StartMicrosoftSSOAuth creates the Kiro portal request.
func (ka *KiroAuth) StartMicrosoftSSOAuth() (sessionID, authorizationURL string, expiresIn int, err error) {
	verifier, err := randomURLSafe(32)
	if err != nil {
		return "", "", 0, fmt.Errorf("generate portal code_challenge material: %w", err)
	}
	state, err := randomURLSafe(32)
	if err != nil {
		return "", "", 0, fmt.Errorf("generate OAuth state: %w", err)
	}

	now := time.Now()
	s := &microsoftSSOSession{
		ID:           uuid.NewString(),
		Provider:     "microsoft-sso",
		PortalState:  state,
		CodeVerifier: verifier,
		ExpiresAt:    now.Add(microsoftSSOSessionTTL),
		stage:        microsoftSSOWaitingForPortal,
	}

	microsoftSSOSessionsMu.Lock()
	expiredSessions := removeExpiredMicrosoftSSOSessionsLocked(now)
	if len(microsoftSSOSessions) >= microsoftSSOMaxSessions {
		microsoftSSOSessionsMu.Unlock()
		for _, expired := range expiredSessions {
			discardDetachedMicrosoftSSOSession(expired)
		}
		return "", "", 0, fmt.Errorf("too many Microsoft SSO sessions; cancel an existing login and try again")
	}
	microsoftSSOSessions[s.ID] = s
	s.timer = time.AfterFunc(microsoftSSOSessionTTL, func() {
		discardMicrosoftSSOSession(s.ID, s)
	})
	microsoftSSOSessionsMu.Unlock()

	for _, expired := range expiredSessions {
		discardDetachedMicrosoftSSOSession(expired)
	}

	q := url.Values{}
	q.Set("state", state)
	q.Set("code_challenge", pkceChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("redirect_uri", microsoftLoopbackBaseURL)
	q.Set("redirect_from", microsoftSSORedirectSource)

	return s.ID, microsoftPortalSignInURL + "?" + q.Encode(), int(microsoftSSOSessionTTL.Seconds()), nil
}

func KiroSocialDefaultLoopbackURL() string {
	return microsoftLoopbackBaseURL + KiroSocialDefaultLoopbackPath
}

// StartKiroSocialAuth creates the Kiro Social login request (Google or GitHub).
func (ka *KiroAuth) StartKiroSocialAuth(provider string) (sessionID, authorizationURL string, expiresIn int, err error) {
	sessionID, authorizationURL, expiresIn, _, err = ka.StartKiroSocialAuthWithRedirect(provider, SocialRedirectURI)
	return sessionID, authorizationURL, expiresIn, err
}

// StartKiroSocialAuthWithRedirect creates a Kiro Social login request with an explicit redirect URI.
func (ka *KiroAuth) StartKiroSocialAuthWithRedirect(provider, redirectURI string) (sessionID, authorizationURL string, expiresIn int, state string, err error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider != "google" && provider != "github" {
		return "", "", 0, "", fmt.Errorf("unsupported Kiro social provider")
	}
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		redirectURI = SocialRedirectURI
	}

	verifier, err := randomURLSafe(32)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("generate PKCE verifier material: %w", err)
	}
	state, err = randomURLSafe(32)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("generate OAuth state: %w", err)
	}

	now := time.Now()
	s := &microsoftSSOSession{
		ID:           uuid.NewString(),
		Provider:     provider,
		PortalState:  state,
		CodeVerifier: verifier,
		RedirectURI:  redirectURI,
		ExpiresAt:    now.Add(microsoftSSOSessionTTL),
		stage:        microsoftSSOWaitingForPortal,
	}

	microsoftSSOSessionsMu.Lock()
	expiredSessions := removeExpiredMicrosoftSSOSessionsLocked(now)
	if len(microsoftSSOSessions) >= microsoftSSOMaxSessions {
		microsoftSSOSessionsMu.Unlock()
		for _, expired := range expiredSessions {
			discardDetachedMicrosoftSSOSession(expired)
		}
		return "", "", 0, "", fmt.Errorf("too many SSO sessions; cancel an existing login and try again")
	}
	microsoftSSOSessions[s.ID] = s
	s.timer = time.AfterFunc(microsoftSSOSessionTTL, func() {
		discardMicrosoftSSOSession(s.ID, s)
	})
	microsoftSSOSessionsMu.Unlock()

	for _, expired := range expiredSessions {
		discardDetachedMicrosoftSSOSession(expired)
	}

	idp := "Google"
	if strings.EqualFold(provider, "github") {
		idp = "Github"
	}

	authURL := fmt.Sprintf("https://prod.us-east-1.auth.desktop.kiro.dev/login?idp=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s&prompt=select_account",
		idp,
		url.QueryEscape(redirectURI),
		pkceChallenge(verifier),
		state,
	)

	return s.ID, authURL, int(microsoftSSOSessionTTL.Seconds()), state, nil
}

// ContinueKiroSocialAuthByState consumes a Kiro social callback URL and resolves the session by OAuth state.
func (ka *KiroAuth) ContinueKiroSocialAuthByState(callbackURL string) (string, *MicrosoftSSOProgress, error) {
	state, err := kiroSocialCallbackState(callbackURL)
	if err != nil {
		return "", nil, err
	}
	session := getKiroSocialSessionByState(state)
	if session == nil {
		return "", nil, fmt.Errorf("Kiro social session not found or expired")
	}
	progress, err := ka.ContinueKiroSocialAuth(session.ID, callbackURL)
	return session.Provider, progress, err
}

// ContinueKiroSocialAuth consumes one pasted callback URL.
func (ka *KiroAuth) ContinueKiroSocialAuth(sessionID, callbackURL string) (*MicrosoftSSOProgress, error) {
	session := getMicrosoftSSOSession(strings.TrimSpace(sessionID))
	if session == nil {
		return nil, fmt.Errorf("Kiro social session not found or expired")
	}

	session.mu.Lock()
	defer func() {
		if session.canceled.Load() {
			clearMicrosoftSSOSessionLocked(session)
		}
		session.mu.Unlock()
	}()

	if session.Provider != "google" && session.Provider != "github" {
		return nil, fmt.Errorf("Kiro social session has an invalid provider")
	}
	if session.canceled.Load() || time.Now().After(session.ExpiresAt) {
		retireMicrosoftSSOSessionLocked(session)
		return nil, fmt.Errorf("Kiro social session expired or canceled")
	}

	redirectURI := strings.TrimSpace(session.RedirectURI)
	if redirectURI == "" {
		redirectURI = SocialRedirectURI
	}
	callback, err := parseKiroSocialCallbackForRedirect(callbackURL, redirectURI)
	if err != nil {
		return nil, err
	}
	q := callback.Query()
	if errCode, err := optionalSingleQueryValue(q, "error"); err != nil {
		return nil, err
	} else if errCode != "" {
		description, _ := optionalSingleQueryValue(q, "error_description")
		retireMicrosoftSSOSessionLocked(session)
		return nil, fmt.Errorf("Kiro social sign-in failed: %s%s", errCode, formatOAuthDescription(description))
	}
	state, err := requiredSingleQueryValue(q, "state")
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(state, session.PortalState) {
		return nil, fmt.Errorf("Kiro social callback state does not match this login session")
	}
	code, err := requiredSingleQueryValue(q, "code")
	if err != nil {
		return nil, err
	}
	if len(code) > 8192 {
		return nil, fmt.Errorf("Kiro social authorization code is too long")
	}

	token, err := ka.exchangeKiroSocialCode(code, session.CodeVerifier, redirectURI)
	if err != nil {
		retireMicrosoftSSOSessionLocked(session)
		return nil, err
	}
	retireMicrosoftSSOSessionLocked(session)

	metadata := parseExternalTokenMetadata(token.GetAccessToken())
	userID := ""
	if metadata.Issuer != "" && metadata.ObjectID != "" {
		userID = strings.TrimRight(metadata.Issuer, "/") + "." + metadata.ObjectID
	}
	return &MicrosoftSSOProgress{Result: &MicrosoftSSOResult{
		AccessToken:   token.GetAccessToken(),
		RefreshToken:  token.GetRefreshToken(),
		ProfileArn:    token.GetProfileArn(),
		TokenEndpoint: "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token",
		Email:         metadata.Email,
		UserID:        userID,
		ExpiresAt:     time.Now().Unix() + int64(token.GetExpiresIn()),
	}}, nil
}

// ContinueMicrosoftSSOAuth consumes one pasted callback URL.
func (ka *KiroAuth) ContinueMicrosoftSSOAuth(sessionID, callbackURL string) (*MicrosoftSSOProgress, error) {
	session := getMicrosoftSSOSession(strings.TrimSpace(sessionID))
	if session == nil {
		return nil, fmt.Errorf("Microsoft SSO session not found or expired")
	}

	session.mu.Lock()
	defer func() {
		if session.canceled.Load() {
			clearMicrosoftSSOSessionLocked(session)
		}
		session.mu.Unlock()
	}()

	if session.Provider != "microsoft-sso" {
		return nil, fmt.Errorf("Microsoft SSO session provider does not match")
	}
	if session.canceled.Load() {
		return nil, fmt.Errorf("Microsoft SSO session not found or expired")
	}
	if time.Now().After(session.ExpiresAt) {
		retireMicrosoftSSOSessionLocked(session)
		return nil, fmt.Errorf("Microsoft SSO session expired")
	}

	switch session.stage {
	case microsoftSSOWaitingForPortal:
		return ka.continueMicrosoftPortalLeg(session, callbackURL)
	case microsoftSSOWaitingForProvider:
		return ka.continueMicrosoftProviderLeg(session, callbackURL)
	default:
		return nil, fmt.Errorf("Microsoft SSO session is in an invalid state")
	}
}

func (ka *KiroAuth) continueMicrosoftPortalLeg(session *microsoftSSOSession, rawURL string) (*MicrosoftSSOProgress, error) {
	callback, err := parseMicrosoftLoopbackCallback(rawURL, microsoftPortalCallback)
	if err != nil {
		return nil, err
	}
	q := callback.Query()

	if errCode, err := optionalSingleQueryValue(q, "error"); err != nil {
		return nil, err
	} else if errCode != "" {
		description, _ := optionalSingleQueryValue(q, "error_description")
		retireMicrosoftSSOSessionLocked(session)
		return nil, fmt.Errorf("Kiro sign-in failed: %s%s", errCode, formatOAuthDescription(description))
	}

	if state, err := optionalSingleQueryValue(q, "state"); err != nil {
		return nil, err
	} else if state != "" && !constantTimeEqual(state, session.PortalState) {
		return nil, fmt.Errorf("Kiro callback state does not match this login session")
	}

	loginOption, err := optionalSingleQueryValue(q, "login_option")
	if err != nil {
		return nil, err
	}
	if loginOption != "" &&
		!strings.EqualFold(loginOption, MicrosoftSSOAuthMethod) &&
		!strings.EqualFold(loginOption, "azuread") &&
		!strings.EqualFold(loginOption, "idc") {
		return nil, fmt.Errorf("login method does not support login_option %q", loginOption)
	}

	issuerURL, err := requiredSingleQueryValue(q, "issuer_url")
	if err != nil {
		return nil, err
	}
	clientID, err := requiredSingleQueryValue(q, "client_id")
	if err != nil {
		return nil, err
	}
	scopes, err := requiredSingleQueryValue(q, "scopes")
	if err != nil {
		return nil, err
	}
	loginHint, err := optionalSingleQueryValue(q, "login_hint")
	if err != nil {
		return nil, err
	}
	if len(loginHint) > 320 {
		return nil, fmt.Errorf("Microsoft login_hint is too long")
	}
	if _, err := uuid.Parse(clientID); err != nil {
		return nil, fmt.Errorf("Microsoft client_id is not a valid UUID")
	}
	scopes, err = validateMicrosoftScopes(scopes, clientID)
	if err != nil {
		return nil, err
	}

	authorizationEndpoint, tokenEndpoint, err := ka.discoverMicrosoftOIDC(issuerURL)
	if err != nil {
		return nil, err
	}
	if session.canceled.Load() {
		retireMicrosoftSSOSessionLocked(session)
		return nil, fmt.Errorf("Microsoft SSO session was canceled")
	}
	verifier, err := randomURLSafe(32)
	if err != nil {
		return nil, fmt.Errorf("generate Microsoft PKCE verifier: %w", err)
	}
	state, err := randomURLSafe(32)
	if err != nil {
		return nil, fmt.Errorf("generate Microsoft OAuth state: %w", err)
	}

	session.providerLeg = &microsoftProviderLeg{
		State:                 state,
		CodeVerifier:          verifier,
		IssuerURL:             strings.TrimRight(strings.TrimSpace(issuerURL), "/"),
		AuthorizationEndpoint: authorizationEndpoint,
		TokenEndpoint:         tokenEndpoint,
		ClientID:              clientID,
		Scopes:                scopes,
	}
	session.stage = microsoftSSOWaitingForProvider

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", microsoftLoopbackBaseURL+microsoftOAuthCallback)
	params.Set("scope", scopes)
	params.Set("code_challenge", pkceChallenge(verifier))
	params.Set("code_challenge_method", "S256")
	params.Set("response_mode", "query")
	params.Set("state", state)
	if loginHint != "" {
		params.Set("login_hint", loginHint)
	}

	return &MicrosoftSSOProgress{
		AuthorizationURL: authorizationEndpoint + "?" + params.Encode(),
	}, nil
}

func (ka *KiroAuth) continueMicrosoftProviderLeg(session *microsoftSSOSession, rawURL string) (*MicrosoftSSOProgress, error) {
	callback, err := parseMicrosoftLoopbackCallback(rawURL, microsoftOAuthCallback)
	if err != nil {
		return nil, err
	}
	leg := session.providerLeg
	if leg == nil {
		return nil, fmt.Errorf("Microsoft SSO provider state is missing")
	}
	q := callback.Query()
	state, err := requiredSingleQueryValue(q, "state")
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(state, leg.State) {
		return nil, fmt.Errorf("Microsoft callback state does not match this login session")
	}
	if errCode, err := optionalSingleQueryValue(q, "error"); err != nil {
		return nil, err
	} else if errCode != "" {
		description, _ := optionalSingleQueryValue(q, "error_description")
		retireMicrosoftSSOSessionLocked(session)
		return nil, fmt.Errorf("Microsoft authorization failed: %s%s", errCode, formatOAuthDescription(description))
	}
	code, err := requiredSingleQueryValue(q, "code")
	if err != nil {
		return nil, err
	}
	if len(code) > 8192 {
		return nil, fmt.Errorf("Microsoft authorization code is too long")
	}

	token, err := ka.exchangeMicrosoftAuthorizationCode(leg, code)
	if err != nil {
		retireMicrosoftSSOSessionLocked(session)
		return nil, err
	}
	if session.canceled.Load() {
		retireMicrosoftSSOSessionLocked(session)
		return nil, fmt.Errorf("Microsoft SSO session was canceled")
	}
	metadata := parseExternalTokenMetadata(token.AccessToken)
	if metadata.Issuer != "" && !sameNormalizedURL(metadata.Issuer, leg.IssuerURL) {
		retireMicrosoftSSOSessionLocked(session)
		return nil, fmt.Errorf("Microsoft access token issuer does not match the login issuer")
	}

	userID := ""
	if metadata.Issuer != "" && metadata.ObjectID != "" {
		userID = strings.TrimRight(metadata.Issuer, "/") + "." + metadata.ObjectID
	}
	result := &MicrosoftSSOResult{
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
		ClientID:      leg.ClientID,
		TokenEndpoint: leg.TokenEndpoint,
		IssuerURL:     leg.IssuerURL,
		Scopes:        leg.Scopes,
		Email:         metadata.Email,
		UserID:        userID,
		ExpiresAt:     time.Now().Unix() + int64(token.ExpiresIn),
	}
	retireMicrosoftSSOSessionLocked(session)
	return &MicrosoftSSOProgress{Result: result}, nil
}

// RefreshMicrosoftSSOToken refreshes Microsoft Enterprise SSO tokens against Entra ID token endpoint.
func (ka *KiroAuth) RefreshMicrosoftSSOToken(ctx context.Context, creds *KiroCredentials) (*KiroCredentials, error) {
	if creds == nil || creds.RefreshToken == "" || creds.ClientID == "" || creds.TokenEndpoint == "" {
		return nil, fmt.Errorf("Microsoft SSO refresh requires refreshToken, clientID, and tokenEndpoint")
	}

	normalizedScopes, err := validateMicrosoftScopes(creds.Scopes, creds.ClientID)
	if err != nil {
		return nil, err
	}
	if err := ValidateExternalIdpEndpoint(creds.TokenEndpoint); err != nil {
		return nil, err
	}
	if creds.IssuerURL != "" {
		if err := ValidateExternalIdpEndpoint(creds.IssuerURL); err != nil {
			return nil, err
		}
	}

	form := url.Values{}
	form.Set("client_id", creds.ClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", creds.RefreshToken)
	form.Set("scope", normalizedScopes)

	token, err := ka.postExternalIdpToken(creds.TokenEndpoint, creds.IssuerURL, form)
	if err != nil {
		return nil, fmt.Errorf("Microsoft SSO token refresh failed: %w", err)
	}

	newCreds := *creds
	newCreds.AccessToken = token.AccessToken
	if token.RefreshToken != "" {
		newCreds.RefreshToken = token.RefreshToken
	}
	if token.ExpiresIn > 0 {
		newCreds.ExpiresAt = time.Now().Unix() + int64(token.ExpiresIn)
	}
	newCreds.LastRefreshed = time.Now().Unix()
	return &newCreds, nil
}

func parseMicrosoftLoopbackCallback(rawURL, expectedPath string) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("callback URL is required")
	}
	if len(rawURL) > microsoftSSOMaxCallbackLen {
		return nil, fmt.Errorf("callback URL is too long")
	}
	u, err := url.Parse(rawURL)
	if err != nil || !u.IsAbs() || u.Opaque != "" {
		return nil, fmt.Errorf("callback URL is invalid")
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return nil, fmt.Errorf("callback URL scheme must be http")
	}
	if u.User != nil || u.Fragment != "" || u.Port() != "3128" {
		return nil, fmt.Errorf("callback URL contains forbidden URL components")
	}
	if !strings.EqualFold(u.Hostname(), "localhost") {
		return nil, fmt.Errorf("callback URL host must be localhost")
	}
	if expectedPath != microsoftPortalCallback && expectedPath != microsoftOAuthCallback {
		return nil, fmt.Errorf("callback URL path is unsupported")
	}
	if u.Path != expectedPath {
		return nil, fmt.Errorf("callback URL path must be %s", expectedPath)
	}
	return u, nil
}

func parseKiroSocialCallback(rawURL string) (*url.URL, error) {
	return parseKiroSocialCallbackForRedirect(rawURL, SocialRedirectURI)
}

func parseKiroSocialCallbackForRedirect(rawURL, redirectURI string) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("callback URL is required")
	}
	if len(rawURL) > microsoftSSOMaxCallbackLen {
		return nil, fmt.Errorf("callback URL is too long")
	}
	u, err := url.Parse(rawURL)
	if err != nil || !u.IsAbs() || u.Opaque != "" {
		return nil, fmt.Errorf("callback URL is invalid")
	}
	expected, err := url.Parse(strings.TrimSpace(redirectURI))
	if err != nil || !expected.IsAbs() || expected.Opaque != "" {
		return nil, fmt.Errorf("Kiro social redirect URI is invalid")
	}
	if !strings.EqualFold(expected.Scheme, "kiro") && !strings.EqualFold(expected.Scheme, "http") {
		return nil, fmt.Errorf("Kiro social redirect URI scheme is unsupported")
	}
	if !strings.EqualFold(u.Scheme, expected.Scheme) || !strings.EqualFold(u.Hostname(), expected.Hostname()) || u.Port() != expected.Port() || u.Path != expected.Path {
		return nil, fmt.Errorf("callback URL does not match the Kiro social redirect URI")
	}
	if u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("callback URL contains forbidden URL components")
	}
	if strings.EqualFold(expected.Scheme, "kiro") {
		if !strings.EqualFold(expected.Hostname(), "kiro.kiroAgent") || expected.Port() != "" || expected.Path != "/authenticate-success" {
			return nil, fmt.Errorf("Kiro social custom redirect URI is invalid")
		}
	} else {
		if !strings.EqualFold(expected.Hostname(), "localhost") || expected.Port() != "3128" || expected.Path != KiroSocialDefaultLoopbackPath {
			return nil, fmt.Errorf("Kiro social loopback redirect URI is invalid")
		}
	}
	return u, nil
}

func kiroSocialCallbackState(rawURL string) (string, error) {
	callback, err := parseKiroSocialCallbackForRedirect(rawURL, KiroSocialDefaultLoopbackURL())
	if err != nil {
		if callback, errCustom := parseKiroSocialCallback(rawURL); errCustom == nil {
			return requiredSingleQueryValue(callback.Query(), "state")
		}
		return "", err
	}
	return requiredSingleQueryValue(callback.Query(), "state")
}

func requiredSingleQueryValue(q url.Values, key string) (string, error) {
	value, err := optionalSingleQueryValue(q, key)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("callback URL is missing %s", key)
	}
	return value, nil
}

func optionalSingleQueryValue(q url.Values, key string) (string, error) {
	values, ok := q[key]
	if !ok {
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("callback URL contains duplicate %s values", key)
	}
	return strings.TrimSpace(values[0]), nil
}

func validateMicrosoftScopes(raw, clientID string) (string, error) {
	if len(raw) > 4096 {
		return "", fmt.Errorf("Microsoft scopes are too long")
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 || len(fields) > 16 {
		return "", fmt.Errorf("Microsoft scopes are invalid")
	}
	standard := map[string]bool{
		"openid": true, "profile": true, "email": true, "offline_access": true,
	}
	kiroScopes := map[string]bool{
		"codewhisperer:completions":     true,
		"codewhisperer:analysis":        true,
		"codewhisperer:conversations":   true,
		"codewhisperer:transformations": true,
		"codewhisperer:taskassist":      true,
	}
	resourcePrefix := "api://" + clientID + "/"
	seen := make(map[string]bool)
	hasOfflineAccess := false
	hasKiroScope := false
	normalized := make([]string, 0, len(fields))
	for _, scope := range fields {
		if seen[scope] {
			continue
		}
		switch {
		case standard[scope]:
			hasOfflineAccess = hasOfflineAccess || scope == "offline_access"
		case strings.HasPrefix(scope, resourcePrefix) && kiroScopes[strings.TrimPrefix(scope, resourcePrefix)]:
			hasKiroScope = true
		default:
			return "", fmt.Errorf("Microsoft scope %q is not expected for Kiro", scope)
		}
		seen[scope] = true
		normalized = append(normalized, scope)
	}
	if !hasOfflineAccess {
		return "", fmt.Errorf("Microsoft scopes must include offline_access")
	}
	if !hasKiroScope {
		return "", fmt.Errorf("Microsoft scopes do not contain a Kiro resource scope")
	}
	return strings.Join(normalized, " "), nil
}

func ValidateExternalIdpEndpoint(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !u.IsAbs() || u.Opaque != "" {
		return fmt.Errorf("external IdP URL is invalid")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("external IdP URL must use https")
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("external IdP URL contains forbidden URL components")
	}
	if port := u.Port(); port != "" && port != "443" {
		return fmt.Errorf("external IdP URL must use the default https port")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || net.ParseIP(host) != nil {
		return fmt.Errorf("external IdP host is invalid")
	}
	allowedHosts := map[string]bool{
		"login.microsoftonline.com":        true,
		"login.microsoftonline.us":         true,
		"login.partner.microsoftonline.cn": true,
	}
	if allowedHosts[host] {
		return nil
	}
	return fmt.Errorf("external IdP host %q is not allow-listed", host)
}

func (ka *KiroAuth) discoverMicrosoftOIDC(issuerURL string) (authorizationEndpoint, tokenEndpoint string, err error) {
	issuer, tenant, err := parseMicrosoftIssuer(issuerURL)
	if err != nil {
		return "", "", err
	}
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(issuer.String(), "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", "", fmt.Errorf("build Microsoft discovery request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := ka.noRedirectClient().Do(request)
	if err != nil {
		return "", "", fmt.Errorf("Microsoft OIDC discovery failed: %w", err)
	}
	defer response.Body.Close()
	body, err := readBoundedBody(response.Body, microsoftSSOMaxResponse)
	if err != nil {
		return "", "", fmt.Errorf("read Microsoft OIDC discovery response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", "", fmt.Errorf("Microsoft OIDC discovery failed with HTTP %d", response.StatusCode)
	}
	var document struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return "", "", fmt.Errorf("parse Microsoft OIDC discovery response: %w", err)
	}
	if !sameNormalizedURL(document.Issuer, issuer.String()) {
		return "", "", fmt.Errorf("Microsoft OIDC discovery issuer does not match the requested issuer")
	}
	if err := validateMicrosoftDiscoveredEndpoint(document.AuthorizationEndpoint, issuer, tenant, "/oauth2/v2.0/authorize"); err != nil {
		return "", "", fmt.Errorf("Microsoft authorization endpoint rejected: %w", err)
	}
	if err := validateMicrosoftDiscoveredEndpoint(document.TokenEndpoint, issuer, tenant, "/oauth2/v2.0/token"); err != nil {
		return "", "", fmt.Errorf("Microsoft token endpoint rejected: %w", err)
	}
	return document.AuthorizationEndpoint, document.TokenEndpoint, nil
}

func parseMicrosoftIssuer(raw string) (*url.URL, string, error) {
	if err := ValidateExternalIdpEndpoint(raw); err != nil {
		return nil, "", err
	}
	u, _ := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if u.RawQuery != "" {
		return nil, "", fmt.Errorf("Microsoft issuer must not contain a query")
	}
	segments := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(segments) != 2 || !strings.EqualFold(segments[1], "v2.0") {
		return nil, "", fmt.Errorf("Microsoft issuer must end with /<tenant>/v2.0")
	}
	tenant, err := url.PathUnescape(segments[0])
	if err != nil {
		return nil, "", fmt.Errorf("Microsoft issuer tenant is invalid")
	}
	if _, err := uuid.Parse(tenant); err != nil {
		return nil, "", fmt.Errorf("Microsoft issuer tenant must be a UUID")
	}
	return u, tenant, nil
}

func validateMicrosoftDiscoveredEndpoint(raw string, issuer *url.URL, tenant, suffix string) error {
	if err := ValidateExternalIdpEndpoint(raw); err != nil {
		return err
	}
	u, _ := url.Parse(strings.TrimSpace(raw))
	if !strings.EqualFold(u.Hostname(), issuer.Hostname()) {
		return fmt.Errorf("endpoint host does not match issuer host")
	}
	if u.RawQuery != "" {
		return fmt.Errorf("endpoint must not contain a query")
	}
	expected := "/" + tenant + suffix
	if !strings.EqualFold(strings.TrimRight(u.EscapedPath(), "/"), expected) {
		return fmt.Errorf("endpoint does not match the issuer tenant")
	}
	return nil
}

type externalIdpTokenResponse struct {
	AccessToken      string `json:"access_token"`
	AccessTokenAlt   string `json:"accessToken"`
	RefreshToken     string `json:"refresh_token"`
	RefreshTokenAlt  string `json:"refreshToken"`
	ProfileArn       string `json:"profile_arn"`
	ProfileArnAlt    string `json:"profileArn"`
	ExpiresIn        int    `json:"expires_in"`
	ExpiresInAlt     int    `json:"expiresIn"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (t *externalIdpTokenResponse) GetAccessToken() string {
	if t.AccessToken != "" {
		return t.AccessToken
	}
	return t.AccessTokenAlt
}

func (t *externalIdpTokenResponse) GetRefreshToken() string {
	if t.RefreshToken != "" {
		return t.RefreshToken
	}
	return t.RefreshTokenAlt
}

func (t *externalIdpTokenResponse) GetProfileArn() string {
	if t.ProfileArn != "" {
		return t.ProfileArn
	}
	return t.ProfileArnAlt
}

func (t *externalIdpTokenResponse) GetExpiresIn() int {
	if t.ExpiresIn > 0 {
		return t.ExpiresIn
	}
	if t.ExpiresInAlt > 0 {
		return t.ExpiresInAlt
	}
	return 3600
}

func (ka *KiroAuth) exchangeMicrosoftAuthorizationCode(leg *microsoftProviderLeg, code string) (*externalIdpTokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", leg.ClientID)
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Set("redirect_uri", microsoftLoopbackBaseURL+microsoftOAuthCallback)
	form.Set("code_verifier", leg.CodeVerifier)
	form.Set("scope", leg.Scopes)
	token, err := ka.postExternalIdpToken(leg.TokenEndpoint, leg.IssuerURL, form)
	if err != nil {
		return nil, fmt.Errorf("Microsoft token exchange failed: %w", err)
	}
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("Microsoft token exchange did not return a refresh token")
	}
	return token, nil
}

func (ka *KiroAuth) postExternalIdpToken(tokenEndpoint, issuerURL string, form url.Values) (*externalIdpTokenResponse, error) {
	if err := ValidateExternalIdpEndpoint(tokenEndpoint); err != nil {
		return nil, fmt.Errorf("external IdP token endpoint rejected: %w", err)
	}
	if strings.TrimSpace(issuerURL) != "" {
		issuer, tenant, err := parseMicrosoftIssuer(issuerURL)
		if err != nil {
			return nil, fmt.Errorf("external IdP issuer rejected: %w", err)
		}
		if err := validateMicrosoftDiscoveredEndpoint(tokenEndpoint, issuer, tenant, "/oauth2/v2.0/token"); err != nil {
			return nil, fmt.Errorf("external IdP token endpoint rejected: %w", err)
		}
	}
	request, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build external IdP token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := ka.noRedirectClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("external IdP token request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := readBoundedBody(response.Body, microsoftSSOMaxResponse)
	if err != nil {
		return nil, fmt.Errorf("read external IdP token response: %w", err)
	}
	var token externalIdpTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parse external IdP token response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if token.Error != "" {
			return nil, fmt.Errorf("HTTP %d: %s%s", response.StatusCode, token.Error, formatOAuthDescription(token.ErrorDescription))
		}
		return nil, fmt.Errorf("external IdP token endpoint returned HTTP %d", response.StatusCode)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, fmt.Errorf("external IdP token response is missing access_token")
	}
	if token.ExpiresIn <= 0 {
		return nil, fmt.Errorf("external IdP token response has invalid expires_in")
	}
	return &token, nil
}

func (ka *KiroAuth) exchangeKiroSocialCode(code, codeVerifier, redirectURI string) (*externalIdpTokenResponse, error) {
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		redirectURI = SocialRedirectURI
	}
	payload, err := json.Marshal(map[string]string{
		"code":          strings.TrimSpace(code),
		"code_verifier": codeVerifier,
		"redirect_uri":  redirectURI,
	})
	if err != nil {
		return nil, fmt.Errorf("build Kiro social token request: %w", err)
	}
	request, err := http.NewRequest(
		http.MethodPost,
		"https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token",
		strings.NewReader(string(payload)),
	)
	if err != nil {
		return nil, fmt.Errorf("build Kiro social token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := ka.noRedirectClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("Kiro social token exchange failed: %w", err)
	}
	defer response.Body.Close()
	body, err := readBoundedBody(response.Body, microsoftSSOMaxResponse)
	if err != nil {
		return nil, fmt.Errorf("read Kiro social token response: %w", err)
	}
	var token externalIdpTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parse Kiro social token response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if token.Error != "" {
			return nil, fmt.Errorf("Kiro social token exchange failed: %s%s", token.Error, formatOAuthDescription(token.ErrorDescription))
		}
		return nil, fmt.Errorf("Kiro social token endpoint returned HTTP %d", response.StatusCode)
	}
	if strings.TrimSpace(token.GetAccessToken()) == "" {
		return nil, fmt.Errorf("Kiro social token response is missing access token")
	}
	if strings.TrimSpace(token.GetRefreshToken()) == "" {
		return nil, fmt.Errorf("Kiro social token response is missing refresh token")
	}
	return &token, nil
}

type externalTokenMetadata struct {
	Issuer    string
	Email     string
	ObjectID  string
	ExpiresAt int64
}

func parseExternalTokenMetadata(accessToken string) externalTokenMetadata {
	if len(accessToken) == 0 || len(accessToken) > 256<<10 {
		return externalTokenMetadata{}
	}
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return externalTokenMetadata{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return externalTokenMetadata{}
	}
	var claims struct {
		Issuer            string `json:"iss"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		UPN               string `json:"upn"`
		UniqueName        string `json:"unique_name"`
		ObjectID          string `json:"oid"`
		ExpiresAt         int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return externalTokenMetadata{}
	}
	email := ""
	for _, candidate := range []string{claims.Email, claims.PreferredUsername, claims.UPN, claims.UniqueName} {
		if candidate = strings.TrimSpace(candidate); candidate != "" {
			email = candidate
			break
		}
	}
	return externalTokenMetadata{
		Issuer:    strings.TrimRight(strings.TrimSpace(claims.Issuer), "/"),
		Email:     email,
		ObjectID:  strings.TrimSpace(claims.ObjectID),
		ExpiresAt: claims.ExpiresAt,
	}
}

func (ka *KiroAuth) noRedirectClient() *http.Client {
	c := ka.httpClient
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	clone := *c
	if clone.Timeout == 0 {
		clone.Timeout = 30 * time.Second
	}
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

func readBoundedBody(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %s bytes", strconv.FormatInt(limit, 10))
	}
	return body, nil
}

func randomURLSafe(size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func constantTimeEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func sameNormalizedURL(left, right string) bool {
	return strings.EqualFold(strings.TrimRight(strings.TrimSpace(left), "/"), strings.TrimRight(strings.TrimSpace(right), "/"))
}

func formatOAuthDescription(description string) string {
	description = strings.TrimSpace(description)
	if description == "" {
		return ""
	}
	if len(description) > 512 {
		description = description[:512]
	}
	return ": " + description
}

func getMicrosoftSSOSession(sessionID string) *microsoftSSOSession {
	if sessionID == "" {
		return nil
	}
	microsoftSSOSessionsMu.Lock()
	session := microsoftSSOSessions[sessionID]
	if session != nil && time.Now().After(session.ExpiresAt) {
		delete(microsoftSSOSessions, sessionID)
		if session.timer != nil {
			session.timer.Stop()
		}
		session.timer = nil
		microsoftSSOSessionsMu.Unlock()
		discardDetachedMicrosoftSSOSession(session)
		return nil
	}
	microsoftSSOSessionsMu.Unlock()
	return session
}

func getKiroSocialSessionByState(state string) *microsoftSSOSession {
	state = strings.TrimSpace(state)
	if state == "" {
		return nil
	}
	now := time.Now()
	microsoftSSOSessionsMu.Lock()
	var match *microsoftSSOSession
	for id, session := range microsoftSSOSessions {
		if session != nil && now.After(session.ExpiresAt) {
			delete(microsoftSSOSessions, id)
			if session.timer != nil {
				session.timer.Stop()
			}
			session.timer = nil
			go discardDetachedMicrosoftSSOSession(session)
			continue
		}
		if session != nil && (session.Provider == "google" || session.Provider == "github") && constantTimeEqual(session.PortalState, state) {
			match = session
			break
		}
	}
	microsoftSSOSessionsMu.Unlock()
	return match
}

func detachMicrosoftSSOSession(sessionID string, expected *microsoftSSOSession) *microsoftSSOSession {
	if sessionID == "" {
		return nil
	}
	microsoftSSOSessionsMu.Lock()
	current := microsoftSSOSessions[sessionID]
	if current != nil && (expected == nil || current == expected) {
		delete(microsoftSSOSessions, sessionID)
		if current.timer != nil {
			current.timer.Stop()
		}
		current.timer = nil
	} else {
		current = nil
	}
	microsoftSSOSessionsMu.Unlock()
	return current
}

func discardMicrosoftSSOSession(sessionID string, expected *microsoftSSOSession) {
	if session := detachMicrosoftSSOSession(sessionID, expected); session != nil {
		discardDetachedMicrosoftSSOSession(session)
	}
}

func discardDetachedMicrosoftSSOSession(session *microsoftSSOSession) {
	session.canceled.Store(true)
	if session.mu.TryLock() {
		clearMicrosoftSSOSessionLocked(session)
		session.mu.Unlock()
	}
}

func retireMicrosoftSSOSessionLocked(session *microsoftSSOSession) {
	detachMicrosoftSSOSession(session.ID, session)
	session.canceled.Store(true)
	clearMicrosoftSSOSessionLocked(session)
}

func clearMicrosoftSSOSessionLocked(session *microsoftSSOSession) {
	session.Provider = ""
	session.PortalState = ""
	session.CodeVerifier = ""
	session.RedirectURI = ""
	session.providerLeg = nil
}

func removeExpiredMicrosoftSSOSessionsLocked(now time.Time) []*microsoftSSOSession {
	var expired []*microsoftSSOSession
	for id, session := range microsoftSSOSessions {
		if now.After(session.ExpiresAt) {
			delete(microsoftSSOSessions, id)
			if session.timer != nil {
				session.timer.Stop()
			}
			session.timer = nil
			expired = append(expired, session)
		}
	}
	return expired
}

// ListAvailableProfiles lists CodeWhisperer profiles for OAuth/IDC tokens.
func (ka *KiroAuth) ListAvailableProfiles(accessToken, region string) (string, error) {
	if region == "" {
		region = "us-east-1"
	}
	endpoint := fmt.Sprintf("https://codewhisperer.%s.amazonaws.com", url.QueryEscape(region))
	reqBody, _ := json.Marshal(map[string]int{"maxResults": 10})

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return "", fmt.Errorf("build ListAvailableProfiles request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("x-amz-target", "AmazonCodeWhispererService.ListAvailableProfiles")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := ka.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ListAvailableProfiles call failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := readBoundedBody(resp.Body, microsoftSSOMaxResponse)
	if err != nil {
		return "", fmt.Errorf("read ListAvailableProfiles body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("ListAvailableProfiles failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Profiles []struct {
			Arn        string `json:"arn"`
			ProfileArn string `json:"profileArn"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("unmarshal ListAvailableProfiles: %w", err)
	}

	for _, p := range result.Profiles {
		arn := p.Arn
		if arn == "" {
			arn = p.ProfileArn
		}
		if arn != "" {
			parts := strings.Split(arn, ":")
			if len(parts) >= 4 && parts[3] == region {
				return arn, nil
			}
		}
	}
	if len(result.Profiles) > 0 {
		arn := result.Profiles[0].Arn
		if arn == "" {
			arn = result.Profiles[0].ProfileArn
		}
		return arn, nil
	}

	return "", nil
}

// RefreshSocialOrKiroToken refreshes a Kiro social token or AWS SSO token.
func (ka *KiroAuth) RefreshSocialOrKiroToken(refreshToken, clientId, clientSecret, region string) (*externalIdpTokenResponse, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	client := ka.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	// AWS SSO OIDC Refresh (Builder ID or IDC)
	if clientId != "" && clientSecret != "" {
		if region == "" {
			region = "us-east-1"
		}
		endpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com/token", url.QueryEscape(region))
		payload := map[string]string{
			"clientId":     clientId,
			"clientSecret": clientSecret,
			"refreshToken": refreshToken,
			"grantType":    "refresh_token",
		}
		jsonBytes, _ := json.Marshal(payload)

		req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(jsonBytes)))
		if err != nil {
			return nil, fmt.Errorf("build AWS SSO refresh request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("AWS SSO refresh request failed: %w", err)
		}
		defer resp.Body.Close()

		body, err := readBoundedBody(resp.Body, microsoftSSOMaxResponse)
		if err != nil {
			return nil, fmt.Errorf("read AWS SSO refresh response: %w", err)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var token externalIdpTokenResponse
			if err := json.Unmarshal(body, &token); err == nil && token.GetAccessToken() != "" {
				return &token, nil
			}
		}
		return nil, fmt.Errorf("AWS SSO refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Social Auth Refresh (Google/GitHub)
	endpoint := "https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken"
	payload := map[string]string{
		"refreshToken": refreshToken,
	}
	jsonBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(jsonBytes)))
	if err != nil {
		return nil, fmt.Errorf("build social refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("social refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := readBoundedBody(resp.Body, microsoftSSOMaxResponse)
	if err != nil {
		return nil, fmt.Errorf("read social refresh response: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var token externalIdpTokenResponse
		if err := json.Unmarshal(body, &token); err == nil && token.GetAccessToken() != "" {
			return &token, nil
		}
	}

	return nil, fmt.Errorf("social refresh failed with status %d: %s", resp.StatusCode, string(body))
}
