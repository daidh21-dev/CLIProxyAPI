package kiro

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

type AutoDetectedKiroToken struct {
	RefreshToken string `json:"refreshToken"`
	ClientId     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	Region       string `json:"region,omitempty"`
	AuthMethod   string `json:"authMethod,omitempty"`
	ProfileArn   string `json:"profileArn,omitempty"`
}

// AutoDetectKiroToken scans local filesystem for Kiro IDE and AWS SSO cache credentials.
func AutoDetectKiroToken() (*AutoDetectedKiroToken, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get user home dir: %w", err)
	}

	cachePath := filepath.Join(home, ".aws", "sso", "cache")
	entries, err := os.ReadDir(cachePath)
	if err != nil {
		return nil, fmt.Errorf("AWS SSO cache directory not found at %s: %w", cachePath, err)
	}

	var refreshToken string
	var foundFile string
	var tokenData map[string]any

	// 1. Try kiro-auth-token.json first
	kiroTokenFile := filepath.Join(cachePath, "kiro-auth-token.json")
	if content, errRead := os.ReadFile(kiroTokenFile); errRead == nil {
		var data map[string]any
		if errJSON := json.Unmarshal(content, &data); errJSON == nil {
			if rt, ok := data["refreshToken"].(string); ok && strings.HasPrefix(rt, "aorAAAAAG") {
				refreshToken = rt
				foundFile = "kiro-auth-token.json"
				tokenData = data
			}
		}
	}

	// 2. Search all json files if not found yet
	if refreshToken == "" {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			content, errRead := os.ReadFile(filepath.Join(cachePath, entry.Name()))
			if errRead != nil {
				continue
			}
			var data map[string]any
			if errJSON := json.Unmarshal(content, &data); errJSON != nil {
				continue
			}
			if rt, ok := data["refreshToken"].(string); ok && strings.HasPrefix(rt, "aorAAAAAG") {
				refreshToken = rt
				foundFile = entry.Name()
				tokenData = data
				break
			}
		}
	}

	if refreshToken == "" {
		return nil, fmt.Errorf("no valid Kiro refresh token found in AWS SSO cache (%s)", cachePath)
	}

	log.Infof("Found Kiro refresh token in cache file: %s", foundFile)

	result := &AutoDetectedKiroToken{
		RefreshToken: refreshToken,
	}

	if tokenData != nil {
		if r, ok := tokenData["region"].(string); ok {
			result.Region = r
		}
		if am, ok := tokenData["authMethod"].(string); ok {
			result.AuthMethod = am
		}

		if hash, ok := tokenData["clientIdHash"].(string); ok && hash != "" {
			clientFile := filepath.Join(cachePath, hash+".json")
			if cContent, errCRead := os.ReadFile(clientFile); errCRead == nil {
				var cData map[string]any
				if errCJSON := json.Unmarshal(cContent, &cData); errCJSON == nil {
					if cid, ok := cData["clientId"].(string); ok {
						result.ClientId = cid
					}
					if cs, ok := cData["clientSecret"].(string); ok {
						result.ClientSecret = cs
					}
				}
			}
		}
	}

	// Read profile.json from Kiro IDE configuration
	profilePaths := []string{
		filepath.Join(home, "AppData", "Roaming", "Kiro", "User", "globalStorage", "kiro.kiroagent", "profile.json"),
		filepath.Join(home, ".config", "Kiro", "User", "globalStorage", "kiro.kiroagent", "profile.json"),
		filepath.Join(home, "Library", "Application Support", "Kiro", "User", "globalStorage", "kiro.kiroagent", "profile.json"),
	}

	for _, pPath := range profilePaths {
		if pContent, errPRead := os.ReadFile(pPath); errPRead == nil {
			var pData map[string]any
			if errPJSON := json.Unmarshal(pContent, &pData); errPJSON == nil {
				if arn, ok := pData["arn"].(string); ok && arn != "" {
					result.ProfileArn = arn
					break
				}
				if arn, ok := pData["profileArn"].(string); ok && arn != "" {
					result.ProfileArn = arn
					break
				}
			}
		}
	}

	return result, nil
}
