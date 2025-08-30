package auth

import (
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/tionis/patchwork/internal/types"
	sshUtil "github.com/tionis/ssh-tools/util"
)

// AuthenticateToken provides authentication for tokens using ACL cache.
func AuthenticateToken(
	authCache *types.AuthCache,
	username string,
	token, path, reqType string,
	isHuProxy bool,
	clientIP net.IP,
	logger *slog.Logger,
) (bool, string, error) {
	if username == "" {
		// Public namespace, no authentication required
		return true, "public", nil
	}

	if token == "" {
		// Missing token in user namespace should be treated as "public" token
		token = "public"
	}

	// For HuProxy, pass the path as the operation to check against patterns
	// For regular HTTP requests, pass the path for pattern matching
	operation := path
	if !isHuProxy {
		// For regular HTTP requests, we need both the method and path
		// The method determines which patterns to check, the path is what gets matched
		// So we pass the HTTP method as the operation type and path for pattern matching
		operation = path
	}

	// Use auth cache to validate token
	valid, tokenInfo, err := ValidateToken(
		authCache,
		username,
		token,
		reqType,
		operation,
		isHuProxy,
	)
	if err != nil {
		// Handle the case where user doesn't exist (config.yaml not found)
		// When treating missing tokens as "public", this should return "token not found"
		if strings.Contains(err.Error(), "config.yaml not found") && token == "public" {
			return false, "token not found", nil
		}
		
		logger.Error(
			"Token validation error",
			"username",
			username,
			"error",
			err,
			"is_huproxy",
			isHuProxy,
		)

		return false, "validation error", err
	}

	if !valid {
		if tokenInfo == nil {
			return false, "token not found", nil
		}
		return false, "invalid token", nil
	}

	logger.Info("Token authenticated",
		"username", username,
		"path", path,
		"operation", operation,
		"is_admin", tokenInfo.IsAdmin,
		"is_huproxy", isHuProxy,
		"client_ip", clientIP.String())

	return true, "authenticated", nil
}

// ValidateToken checks if a token is valid for a user and operation.
func ValidateToken(
	cache *types.AuthCache,
	username, token, method, path string,
	isHuProxy bool,
) (bool, *types.TokenInfo, error) {
	auth, err := GetUserAuth(cache, username)
	if err != nil {
		return false, nil, err
	}

	tokenInfo, exists := auth.Tokens[token]
	if !exists {
		return false, nil, nil
	}

	// Check if token is expired
	if tokenInfo.ExpiresAt != nil && time.Now().After(*tokenInfo.ExpiresAt) {
		return false, nil, nil
	}

	// For HuProxy requests, check if token has huproxy permissions
	if isHuProxy {
		if len(tokenInfo.HuProxy) == 0 {
			return false, nil, nil
		}

		return sshUtil.MatchPatternList(tokenInfo.HuProxy, path), &tokenInfo, nil
	}

	// For regular HTTP requests, check method-specific permissions
	var patterns []*sshUtil.Pattern

	switch strings.ToUpper(method) {
	case "GET":
		patterns = tokenInfo.GET
	case "POST":
		patterns = tokenInfo.POST
	case "PUT":
		patterns = tokenInfo.PUT
	case "DELETE":
		patterns = tokenInfo.DELETE
	case "PATCH":
		patterns = tokenInfo.PATCH
	case "ADMIN":
		// Admin operations require is_admin flag
		return tokenInfo.IsAdmin, &tokenInfo, nil
	default:
		return false, nil, nil
	}

	if len(patterns) == 0 {
		return false, nil, nil
	}

	return sshUtil.MatchPatternList(patterns, path), &tokenInfo, nil
}
