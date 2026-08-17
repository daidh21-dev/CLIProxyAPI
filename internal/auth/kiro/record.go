package kiro

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	metadataAccessToken             = "access_token"
	metadataRefreshToken            = "refresh_token"
	metadataRefreshTokenFingerprint = "refresh_token_fingerprint"
	metadataOriginalRefreshTokenFP  = "original_refresh_token_fingerprint"
	metadataKiroAPIKey              = "kiro_api_key"
	metadataAuthMethod              = "auth_method"
	metadataClientID                = "client_id"
	metadataClientSecret            = "client_secret"
	metadataRegion                  = "region"
	metadataProfileArn              = "profile_arn"
	metadataTokenEndpoint           = "token_endpoint"
	metadataIssuerURL               = "issuer_url"
	metadataScopes                  = "scopes"
	metadataEmail                   = "email"
	metadataUserID                  = "user_id"
	metadataExpiresAt               = "expires_at"
	metadataLastRefreshed           = "last_refreshed"
	metadataMachineID               = "machine_id"
	metadataBaseURL                 = "base_url"
)

// MetadataString returns the trimmed string metadata value for key.
func MetadataString(meta map[string]any, key string) string {
	if len(meta) == 0 {
		return ""
	}
	value, ok := meta[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}

// MetadataInt64 returns a best-effort int64 metadata value for key.
func MetadataInt64(meta map[string]any, key string) int64 {
	if len(meta) == 0 {
		return 0
	}
	value, ok := meta[key]
	if !ok || value == nil {
		return 0
	}
	switch v := value.(type) {
	case int:
		return int64(v)
	case int8:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case uint:
		return int64(v)
	case uint8:
		return int64(v)
	case uint16:
		return int64(v)
	case uint32:
		return int64(v)
	case uint64:
		return int64(v)
	case float32:
		return int64(v)
	case float64:
		return int64(v)
	case time.Time:
		return v.Unix()
	case string:
		trimmed := strings.TrimSpace(v)
		if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			return parsed
		}
		if parsed, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
			return parsed.Unix()
		}
	}
	return 0
}

// CredentialsFromAuth converts a Kiro auth record into the credential shape used by the auth helpers.
func CredentialsFromAuth(auth *coreauth.Auth) *KiroCredentials {
	if auth == nil {
		return nil
	}
	creds := &KiroCredentials{
		AccessToken:   MetadataString(auth.Metadata, metadataAccessToken),
		RefreshToken:  MetadataString(auth.Metadata, metadataRefreshToken),
		ProfileArn:    MetadataString(auth.Metadata, metadataProfileArn),
		AuthMethod:    MetadataString(auth.Metadata, metadataAuthMethod),
		ClientID:      MetadataString(auth.Metadata, metadataClientID),
		ClientSecret:  MetadataString(auth.Metadata, metadataClientSecret),
		Region:        MetadataString(auth.Metadata, metadataRegion),
		ExpiresAt:     MetadataInt64(auth.Metadata, metadataExpiresAt),
		LastRefreshed: MetadataInt64(auth.Metadata, metadataLastRefreshed),
		TokenEndpoint: MetadataString(auth.Metadata, metadataTokenEndpoint),
		IssuerURL:     MetadataString(auth.Metadata, metadataIssuerURL),
		Scopes:        MetadataString(auth.Metadata, metadataScopes),
		BaseURL:       MetadataString(auth.Metadata, metadataBaseURL),
	}
	if creds.BaseURL == "" && auth.Attributes != nil {
		if u, ok := auth.Attributes["base_url"]; ok && strings.TrimSpace(u) != "" {
			creds.BaseURL = strings.TrimSpace(u)
		}
	}
	if creds.Region == "" {
		creds.Region = DefaultAwsRegion
	}
	return creds
}

// ApplyCredentialsToAuth overwrites a Kiro auth record with refreshed credential metadata.
func ApplyCredentialsToAuth(auth *coreauth.Auth, creds *KiroCredentials) *coreauth.Auth {
	if auth == nil || creds == nil {
		return auth
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	var kiroAPIKey any
	if strings.EqualFold(strings.TrimSpace(creds.AuthMethod), "api_key") {
		kiroAPIKey = creds.AccessToken
	}
	for key, value := range map[string]any{
		metadataAccessToken:   creds.AccessToken,
		metadataRefreshToken:  creds.RefreshToken,
		metadataProfileArn:    creds.ProfileArn,
		metadataAuthMethod:    creds.AuthMethod,
		metadataClientID:      creds.ClientID,
		metadataClientSecret:  creds.ClientSecret,
		metadataRegion:        creds.Region,
		metadataExpiresAt:     creds.ExpiresAt,
		metadataLastRefreshed: creds.LastRefreshed,
		metadataTokenEndpoint: creds.TokenEndpoint,
		metadataIssuerURL:     creds.IssuerURL,
		metadataScopes:        creds.Scopes,
		metadataKiroAPIKey:    kiroAPIKey,
		metadataBaseURL:       creds.BaseURL,
	} {
		if value == nil || value == "" {
			continue
		}
		auth.Metadata[key] = value
	}
	return auth
}

// SetRefreshFingerprints records the current and original refresh token fingerprints.
func SetRefreshFingerprints(auth *coreauth.Auth, currentRefreshToken, originalRefreshToken string) {
	if auth == nil {
		return
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	if current := RefreshTokenFingerprint(currentRefreshToken); current != "" {
		auth.Metadata[metadataRefreshTokenFingerprint] = current
	}
	if original := RefreshTokenFingerprint(originalRefreshToken); original != "" {
		auth.Metadata[metadataOriginalRefreshTokenFP] = original
	}
}

// RefreshTokenFingerprint returns a stable fingerprint for a refresh token.
func RefreshTokenFingerprint(refreshToken string) string {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(refreshToken))
	return hex.EncodeToString(sum[:])
}

// APIKeyFingerprint returns a stable fingerprint for a Kiro API key.
func APIKeyFingerprint(apiKey string) string {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

// EnsureAuthMetadataFingerprint populates the refresh fingerprint metadata if missing.
func EnsureAuthMetadataFingerprint(auth *coreauth.Auth) {
	if auth == nil {
		return
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	if MetadataString(auth.Metadata, metadataRefreshTokenFingerprint) == "" {
		if fp := RefreshTokenFingerprint(MetadataString(auth.Metadata, metadataRefreshToken)); fp != "" {
			auth.Metadata[metadataRefreshTokenFingerprint] = fp
		}
	}
	if MetadataString(auth.Metadata, metadataOriginalRefreshTokenFP) == "" {
		if fp := MetadataString(auth.Metadata, metadataRefreshTokenFingerprint); fp != "" {
			auth.Metadata[metadataOriginalRefreshTokenFP] = fp
		}
	}
}

// DuplicateReason returns a short reason if candidate conflicts with existing Kiro records.
func DuplicateReason(existing, candidate *coreauth.Auth) string {
	if candidate == nil {
		return ""
	}
	if existing == nil {
		return ""
	}
	if strings.TrimSpace(existing.ID) != "" && strings.EqualFold(strings.TrimSpace(existing.ID), strings.TrimSpace(candidate.ID)) {
		return "duplicate auth id"
	}
	if !strings.EqualFold(strings.TrimSpace(existing.Provider), "kiro") || !strings.EqualFold(strings.TrimSpace(candidate.Provider), "kiro") {
		return ""
	}
	candidateRefreshFP := MetadataString(candidate.Metadata, metadataRefreshTokenFingerprint)
	candidateOriginalFP := MetadataString(candidate.Metadata, metadataOriginalRefreshTokenFP)
	candidateAPIKey := MetadataString(candidate.Metadata, metadataKiroAPIKey)
	existingAPIKey := MetadataString(existing.Metadata, metadataKiroAPIKey)
	candidateAPIKeyFP := APIKeyFingerprint(candidateAPIKey)
	existingAPIKeyFP := APIKeyFingerprint(existingAPIKey)
	if candidateRefreshFP != "" && candidateRefreshFP == MetadataString(existing.Metadata, metadataRefreshTokenFingerprint) {
		return "duplicate refresh token"
	}
	if candidateOriginalFP != "" && (candidateOriginalFP == MetadataString(existing.Metadata, metadataOriginalRefreshTokenFP) || candidateOriginalFP == MetadataString(existing.Metadata, metadataRefreshTokenFingerprint)) {
		return "duplicate original refresh token"
	}
	if candidateAPIKeyFP != "" {
		existingAccess := MetadataString(existing.Metadata, metadataAccessToken)
		if candidateAPIKeyFP == existingAPIKeyFP || candidateAPIKey == existingAPIKey || candidateAPIKey == existingAccess || candidateAPIKeyFP == APIKeyFingerprint(existingAccess) {
			return "duplicate API key"
		}
	}
	return ""
}
