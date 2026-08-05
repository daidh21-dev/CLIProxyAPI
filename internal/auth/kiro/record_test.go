package kiro

import (
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestRefreshTokenFingerprint(t *testing.T) {
	if got := RefreshTokenFingerprint(" token "); got == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if got := RefreshTokenFingerprint("token"); got != RefreshTokenFingerprint("token") {
		t.Fatal("expected stable fingerprint")
	}
}

func TestDuplicateReason(t *testing.T) {
	existing := &coreauth.Auth{
		ID:       "kiro-1",
		Provider: "kiro",
		Metadata: map[string]any{
			metadataRefreshTokenFingerprint: RefreshTokenFingerprint("refresh-a"),
			metadataOriginalRefreshTokenFP:  RefreshTokenFingerprint("refresh-a"),
			metadataKiroAPIKey:              "api-key-a",
		},
	}

	candidate := &coreauth.Auth{
		ID:       "kiro-2",
		Provider: "kiro",
		Metadata: map[string]any{
			metadataRefreshTokenFingerprint: RefreshTokenFingerprint("refresh-a"),
		},
	}
	if reason := DuplicateReason(existing, candidate); reason != "duplicate refresh token" {
		t.Fatalf("unexpected duplicate reason: %q", reason)
	}

	candidate = &coreauth.Auth{
		ID:       "kiro-3",
		Provider: "kiro",
		Metadata: map[string]any{
			metadataRefreshTokenFingerprint: RefreshTokenFingerprint("refresh-b"),
			metadataOriginalRefreshTokenFP:  RefreshTokenFingerprint("refresh-a"),
		},
	}
	if reason := DuplicateReason(existing, candidate); reason != "duplicate original refresh token" {
		t.Fatalf("unexpected duplicate reason: %q", reason)
	}

	candidate = &coreauth.Auth{
		ID:       "kiro-4",
		Provider: "kiro",
		Metadata: map[string]any{
			metadataKiroAPIKey: "api-key-a",
		},
	}
	if reason := DuplicateReason(existing, candidate); reason != "duplicate API key" {
		t.Fatalf("unexpected duplicate reason: %q", reason)
	}
}

func TestEnsureAuthMetadataFingerprint(t *testing.T) {
	auth := &coreauth.Auth{
		Metadata: map[string]any{
			metadataRefreshToken: "refresh-token",
		},
	}
	EnsureAuthMetadataFingerprint(auth)
	if got := MetadataString(auth.Metadata, metadataRefreshTokenFingerprint); got == "" {
		t.Fatal("expected refresh fingerprint")
	}
	if got := MetadataString(auth.Metadata, metadataOriginalRefreshTokenFP); got == "" {
		t.Fatal("expected original refresh fingerprint")
	}
}
