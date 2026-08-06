package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// KiroAuthenticator implements the Kiro Builder ID / device-code flow.
type KiroAuthenticator struct {
	Region string
}

// NewKiroAuthenticator constructs a Kiro authenticator with default settings.
func NewKiroAuthenticator() Authenticator {
	return &KiroAuthenticator{Region: kiroauth.DefaultAwsRegion}
}

// Provider returns the provider key for Kiro.
func (KiroAuthenticator) Provider() string { return "kiro" }

// RefreshLead instructs the manager to refresh five minutes before expiry.
func (KiroAuthenticator) RefreshLead() *time.Duration {
	lead := 5 * time.Minute
	return &lead
}

// Login launches a Kiro authentication flow and returns a persisted auth record.
func (a *KiroAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	region := strings.TrimSpace(a.Region)
	if region == "" {
		region = kiroauth.DefaultAwsRegion
	}

	authSvc := kiroauth.NewKiroAuth(cfg, nil)
	if opts.Metadata != nil {
		if token := strings.TrimSpace(opts.Metadata["import_token"]); token != "" {
			creds, err := authSvc.ValidateImportToken(ctx, token)
			if err != nil {
				return nil, err
			}
			email, userID, _ := authSvc.GetUserInfo(ctx, creds.AccessToken, creds.ProfileArn, creds.Region)
			fileName := kiroauth.CredentialFileName(email, userID)
			label := strings.TrimSpace(email)
			if label == "" {
				label = "Kiro AI"
			}
			return &coreauth.Auth{
				ID:       fileName,
				Provider: a.Provider(),
				FileName: fileName,
				Label:    label,
				Metadata: kiroauth.NormalizeKiroMetadata(creds, email, userID),
			}, nil
		}
	}

	if _, err := misc.GenerateRandomState(); err != nil {
		return nil, fmt.Errorf("kiro state generation failed: %w", err)
	}
	reg, err := authSvc.RegisterClient(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("kiro client registration failed: %w", err)
	}
	device, err := authSvc.StartDeviceAuthorization(ctx, reg.ClientID, reg.ClientSecret, "", region)
	if err != nil {
		return nil, fmt.Errorf("kiro device authorization failed: %w", err)
	}
	verificationURL := strings.TrimSpace(device.VerificationURIComplete)
	if verificationURL == "" {
		verificationURL = strings.TrimSpace(device.VerificationURI)
	}
	fmt.Printf("\nTo authenticate, please visit:\n%s\n\n", verificationURL)
	if device.UserCode != "" {
		fmt.Printf("User code: %s\n\n", device.UserCode)
	}
	if !opts.NoBrowser && browser.IsAvailable() && verificationURL != "" {
		if errOpen := browser.OpenURL(verificationURL); errOpen != nil {
			log.Warnf("Failed to open browser automatically: %v", errOpen)
		}
	}

	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(device.ExpiresIn)*time.Second)
	defer cancel()
	interval := time.Duration(device.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	var tokenResp *kiroauth.TokenResponse
	for pollCtx.Err() == nil {
		resp, errPoll := authSvc.PollDeviceToken(pollCtx, reg.ClientID, reg.ClientSecret, device.DeviceCode, region)
		if errPoll == nil && resp != nil && strings.TrimSpace(resp.AccessToken) != "" {
			tokenResp = resp
			break
		}
		if resp != nil && strings.EqualFold(strings.TrimSpace(resp.Error), "slow_down") {
			interval += 5 * time.Second
		}
		time.Sleep(interval)
	}
	if tokenResp == nil {
		return nil, fmt.Errorf("kiro: device authorization expired or cancelled")
	}

	creds := &kiroauth.KiroCredentials{
		AccessToken:   tokenResp.AccessToken,
		RefreshToken:  tokenResp.RefreshToken,
		ProfileArn:    tokenResp.ProfileArn,
		AuthMethod:    "builder-id",
		ClientID:      reg.ClientID,
		ClientSecret:  reg.ClientSecret,
		Region:        region,
		ExpiresAt:     time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix(),
		LastRefreshed: time.Now().Unix(),
	}
	if strings.TrimSpace(creds.ProfileArn) == "" {
		if profileArn, errProfile := authSvc.ResolveProfileArn(ctx, creds); errProfile == nil {
			creds.ProfileArn = profileArn
		}
	}
	if email, userID, errInfo := authSvc.GetUserInfo(ctx, creds.AccessToken, creds.ProfileArn, creds.Region); errInfo == nil {
		fileName := kiroauth.CredentialFileName(email, userID)
		label := strings.TrimSpace(email)
		if label == "" {
			label = "Kiro AI"
		}
		return &coreauth.Auth{
			ID:       fileName,
			Provider: a.Provider(),
			FileName: fileName,
			Label:    label,
			Metadata: kiroauth.NormalizeKiroMetadata(creds, email, userID),
		}, nil
	}
	fileName := fmt.Sprintf("kiro-%d.json", time.Now().Unix())
	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    "Kiro AI",
		Metadata: kiroauth.NormalizeKiroMetadata(creds, "", ""),
	}, nil
}
