package kiro

import (
	"net/url"
	"strings"
	"testing"
)

func TestStartKiroSocialAuthWithRedirectUsesLoopbackURI(t *testing.T) {
	auth := NewKiroAuth(nil, nil)
	sessionID, authURL, expiresIn, state, err := auth.StartKiroSocialAuthWithRedirect("google", KiroSocialDefaultLoopbackURL())
	if err != nil {
		t.Fatalf("StartKiroSocialAuthWithRedirect returned error: %v", err)
	}
	if sessionID == "" || state == "" || expiresIn <= 0 {
		t.Fatalf("expected session id, state, and positive expiry; got session=%q state=%q expiry=%d", sessionID, state, expiresIn)
	}
	t.Cleanup(func() { discardMicrosoftSSOSession(sessionID, nil) })

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("auth URL is invalid: %v", err)
	}
	q := parsed.Query()
	if got := q.Get("idp"); got != "Google" {
		t.Fatalf("expected Google idp, got %q", got)
	}
	if got := q.Get("redirect_uri"); got != KiroSocialDefaultLoopbackURL() {
		t.Fatalf("expected loopback redirect URI %q, got %q", KiroSocialDefaultLoopbackURL(), got)
	}
	if got := q.Get("state"); got != state {
		t.Fatalf("expected state %q, got %q", state, got)
	}
}

func TestParseKiroSocialCallbackForRedirectAcceptsLoopback(t *testing.T) {
	callback := KiroSocialDefaultLoopbackURL() + "?code=code-1&state=state-1"
	parsed, err := parseKiroSocialCallbackForRedirect(callback, KiroSocialDefaultLoopbackURL())
	if err != nil {
		t.Fatalf("parseKiroSocialCallbackForRedirect returned error: %v", err)
	}
	if got := parsed.Query().Get("code"); got != "code-1" {
		t.Fatalf("expected code-1, got %q", got)
	}
}

func TestParseKiroSocialCallbackForRedirectRejectsUnexpectedLoopback(t *testing.T) {
	cases := []string{
		"https://localhost:3128/oauth/callback?code=code-1&state=state-1",
		"http://127.0.0.1:3128/oauth/callback?code=code-1&state=state-1",
		"http://localhost:3129/oauth/callback?code=code-1&state=state-1",
		"http://localhost:3128/other?code=code-1&state=state-1",
		"http://user@localhost:3128/oauth/callback?code=code-1&state=state-1",
		"http://localhost:3128/oauth/callback?code=code-1&state=state-1#fragment",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := parseKiroSocialCallbackForRedirect(tc, KiroSocialDefaultLoopbackURL()); err == nil {
				t.Fatalf("expected %q to be rejected", tc)
			}
		})
	}
}

func TestParseKiroSocialCallbackForRedirectKeepsCustomSchemeFallback(t *testing.T) {
	callback := SocialRedirectURI + "?code=code-1&state=state-1"
	parsed, err := parseKiroSocialCallback(callback)
	if err != nil {
		t.Fatalf("parseKiroSocialCallback returned error: %v", err)
	}
	if got := parsed.Query().Get("state"); got != "state-1" {
		t.Fatalf("expected state-1, got %q", got)
	}
}

func TestKiroSocialCallbackStateRejectsMissingState(t *testing.T) {
	_, err := kiroSocialCallbackState(KiroSocialDefaultLoopbackURL() + "?code=code-1")
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("expected missing state error, got %v", err)
	}
}
