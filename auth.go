package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/armortal/webcrypto-go"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
	"io"
	"net/http"
	"strings"
	"time"
)

// token represents the json data structure of a json after being base64 decoded and uncompressed using gzip
type token struct {
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

// tokenData represents the signed data within a token that is used to authenticate a request
type tokenData struct {
	AllowedWritePaths []string `json:"AllowedWritePaths"` // writing means sending requests in this case
	AllowedReadPaths  []string `json:"AllowedReadPaths"`  // reading mean receiving requests in this case
	ValidBefore       int64    `json:"ValidBefore"`       // -1 means the token is valid forever
	ValidAfter        int64    `json:"ValidAfter"`        // -1 means the token is valid from the beginning of time
}

type webcryptoToken struct {
	Data      string              `json:"data"`
	Algorithm webcrypto.Algorithm `json:"algorithm"`
	Key       string              `json:"key"`
}

func (s *server) authenticateWebcryptoToken(token []byte, path string, isWriteOp bool) (bool, string, error) {
	var t webcryptoToken
	err := json.Unmarshal(token, &t)
	if err != nil {
		return false, "token could not be marshalled", fmt.Errorf("error unmarshalling token: %w", err)
	}
	// TODO import key
	// verify signature key matches namespace owner
	// verify signature of token
	// verify token prefix paths (handle this in it's own method to avoid code duplication)
	return false, "not implemented", errors.New("not implemented")
}

func (s *server) authenticateToken(owner *owner, tokenStr, path string, isWriteOp bool) (bool, string, error) {
	s.logger.Debug("Authenticating token", "owner", owner, "tokenStr", tokenStr, "path", path, "isWriteOp", isWriteOp)
	decodedCompressedToken, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return false, "token could not be decoded", fmt.Errorf("error decoding token: %w", err)
	}
	decodedTokenReader, err := gzip.NewReader(bytes.NewReader(decodedCompressedToken))
	if err != nil {
		return false, "token could not be decompressed", fmt.Errorf("error decompressing token: %w", err)
	}
	decodedToken, err := io.ReadAll(decodedTokenReader)
	if err != nil {
		return false, "", fmt.Errorf("error reading decompressed token: %w", err)
	}
	switch owner.typ {
	case ownerTypeWebcrypto:
		return s.authenticateWebcryptoToken(decodedToken, path, isWriteOp)
	}
	var t token
	err = json.Unmarshal(decodedToken, &t)
	if err != nil {
		s.logger.Error("Error unmarshalling token", err, "decodedToken", string(decodedToken))
		return false, "token could not be marshalled", fmt.Errorf("error unmarshalling token: %w", err)
	}
	signature, err := sshsig.Unarmor([]byte(t.Signature))
	if err != nil {
		s.logger.Error("Error parsing signature", err, "signature", t.Signature)
		return false, "signature could not be parsed", fmt.Errorf("error parsing signature: %w", err)
	}
	dataReader := bytes.NewReader([]byte(t.Data + "\n"))
	err = sshsig.Verify(dataReader, signature, signature.PublicKey, signature.HashAlgorithm, "patch.tionis.dev")
	if err != nil {
		dataReader := bytes.NewReader([]byte(t.Data))
		err = sshsig.Verify(dataReader, signature, signature.PublicKey, signature.HashAlgorithm, "patch.tionis.dev")
		if err != nil {
			s.logger.Error("Error verifying signature", err, "signature", t.Signature, "data", t.Data)
			return false, "signature could not be verified", fmt.Errorf("error verifying signature: %w", err)
		}
	}
	var tokenData tokenData
	err = json.Unmarshal([]byte(t.Data), &tokenData)
	if err != nil {
		return false, "tokenData could not be marshalled", fmt.Errorf("error unmarshalling token data: %w", err)
	}
	if tokenData.ValidBefore != -1 && time.Now().Unix() > tokenData.ValidBefore {
		return false, "token is no longer valid", nil
	}
	if tokenData.ValidAfter != -1 && time.Now().Unix() < tokenData.ValidAfter {
		return false, "token is not yet valid", nil
	}
	keyAllowed, reason, err := s.isKeyAllowed(owner, signature.PublicKey, tokenData, path, isWriteOp)
	if err != nil {
		return false, "error checking key", fmt.Errorf("error checking key: %w", err)
	}
	return keyAllowed, reason, nil
}

func (s *server) githubFetchUserKeys(username string) ([]ssh.PublicKey, error) {
	// send a request to https://github.com/<username>.keys and parse the keys
	s.githubUserKeyMutex.RLock()
	if entry, ok := s.githubUserKeyMap[username]; ok {
		if time.Now().Before(entry.validUntil) {
			s.logger.Debug("Returning cached user keys", "username", username)
			s.githubUserKeyMutex.RUnlock()
			return entry.keys, nil
		}
	}
	s.githubUserKeyMutex.RUnlock()
	response, err := http.Get("https://github.com/" + username + ".keys")
	if err != nil {
		return nil, fmt.Errorf("error fetching user keys: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			s.logger.Error("Error closing response body", err)
		}
	}(response.Body)
	var keys []ssh.PublicKey
	rest, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}
	for len(rest) > 0 {
		var key ssh.PublicKey
		key, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return nil, fmt.Errorf("error parsing authorized key: %w", err)
		}
		keys = append(keys, key)
	}
	s.githubUserKeyMutex.Lock()
	s.githubUserKeyMap[username] = sshPubKeyListEntry{
		keys:       keys,
		validUntil: time.Now().Add(githubUserCacheTTL),
	}
	s.githubUserKeyMutex.Unlock()
	return keys, nil
}

func (s *server) isKeyAllowed(owner *owner, key ssh.PublicKey, tokenData tokenData, path string, isWriteOp bool) (bool, string, error) {
	s.logger.Debug("Checking if key is allowed", "owner", owner, "key", key, "tokenData", tokenData, "path", path, "isWriteOp", isWriteOp)
	switch owner.typ {
	case ownerTypePublicKey:
		signerFingerprint := ssh.FingerprintSHA256(key)
		if signerFingerprint != owner.name {
			s.logger.Debug("Key is not signed by owner", "signerFingerprint", signerFingerprint, "owner", owner)
			return false, "token not signed by key for namespace", nil
		}
		// TODO use pattern lists instead
		if isWriteOp {
			for _, allowedPath := range tokenData.AllowedWritePaths {
				if strings.HasPrefix(path, allowedPath) {
					return true, "", nil
				}
			}
		} else {
			for _, allowedPath := range tokenData.AllowedReadPaths {
				if strings.HasPrefix(path, allowedPath) {
					return true, "", nil
				}
			}
		}
		return false, "token not allowed on path", nil
	case ownerTypeUsername:
		keys, err := s.githubFetchUserKeys(owner.name)
		if err != nil {
			return false, "could not fetch user keys", fmt.Errorf("error fetching user keys: %w", err)
		}
		marshaledKey := key.Marshal()
		s.logger.Debug("Checking if key is allowed", "marshaledKey", string(marshaledKey), "keys", keys)
		for _, k := range keys {
			mk := k.Marshal()
			s.logger.Debug("Checking key", "mk", string(mk), "marshaledKey", string(marshaledKey))
			if bytes.Equal(marshaledKey, mk) {
				s.logger.Debug("Key is allowed, checking path now", "owner", owner, "key", key, "tokenData", tokenData, "path", path, "isWriteOp", isWriteOp)
				// TODO use pattern lists instead
				if isWriteOp {
					for _, allowedPath := range tokenData.AllowedWritePaths {
						if strings.HasPrefix(path, allowedPath) {
							return true, "", nil
						}
					}
				} else {
					for _, allowedPath := range tokenData.AllowedReadPaths {
						if strings.HasPrefix(path, allowedPath) {
							return true, "", nil
						}
					}
				}
			}
		}
		return false, "token not allowed on path", nil
	case ownerTypeGistID:
		//allowedSigners, err := s.githubFetchGistAllowedSSigners(owner.name)
		//if err != nil {
		//	return false, err
		//}
		// TODO implement me
		return false, "not implemented", errors.New("not implemented")
	default:
		return false, "internal error", errors.New("unknown owner type")
	}
}
