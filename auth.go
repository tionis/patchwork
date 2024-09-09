package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/armortal/webcrypto-go"
	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/hiddeco/sshsig"
	log "github.com/sirupsen/logrus"
	sshUtil "github.com/tionis/ssh-tools/util"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
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
type tokenDataJSON struct {
	AllowedWritePaths []string `json:"AllowedWritePaths"` // writing means sending requests in this case
	AllowedReadPaths  []string `json:"AllowedReadPaths"`  // reading mean receiving requests in this case
	ValidBefore       int64    `json:"ValidBefore"`       // -1 means the token is valid forever
	ValidAfter        int64    `json:"ValidAfter"`        // -1 means the token is valid from the beginning of time
}

type tokenData struct {
	AllowedWritePaths []*sshUtil.Pattern `json:"AllowedWritePaths"` // writing means sending requests in this case
	AllowedReadPaths  []*sshUtil.Pattern `json:"AllowedReadPaths"`  // reading mean receiving requests in this case
	ValidBefore       sql.NullTime       `json:"ValidBefore"`       // -1 means the token is valid forever
	ValidAfter        sql.NullTime       `json:"ValidAfter"`        // -1 means the token is valid from the beginning of time
}

type webcryptoToken struct {
	Data      string               `json:"data"`
	Algorithm *webcrypto.Algorithm `json:"algorithm"`
	Signature string               `json:"signature"`
}

func (t *tokenDataJSON) Unmarshal() (tokenData, error) {
	var allowedReadPaths []*sshUtil.Pattern
	for _, line := range t.AllowedReadPaths {
		patt, err := sshUtil.NewPattern(line)
		if err != nil {
			return tokenData{}, fmt.Errorf("failed parsing pattern %s: %w", line, err)
		}
		allowedReadPaths = append(allowedReadPaths, patt)
	}
	var allowedWritePaths []*sshUtil.Pattern
	for _, line := range t.AllowedWritePaths {
		patt, err := sshUtil.NewPattern(line)
		if err != nil {
			return tokenData{}, fmt.Errorf("failed parsing pattern %s: %w", line, err)
		}
		allowedWritePaths = append(allowedWritePaths, patt)
	}
	var validAfter sql.NullTime
	var validBefore sql.NullTime
	if t.ValidBefore != -1 {
		validBefore.Valid = true
		validBefore.Time = time.Unix(t.ValidBefore, 0)
	}
	if t.ValidAfter != -1 {
		validAfter.Valid = true
		validAfter.Time = time.Unix(t.ValidAfter, 0)
	}
	return tokenData{
		AllowedReadPaths:  allowedReadPaths,
		AllowedWritePaths: allowedWritePaths,
		ValidAfter:        validAfter,
		ValidBefore:       validBefore,
	}, nil
}

func (s *server) authenticateWebcryptoToken(owner string, token []byte, path string, isWriteOp bool) (bool, string, error) {
	var wt webcryptoToken
	cleanedOwnerName := strings.ReplaceAll("-", "+", strings.ReplaceAll("_", "/", owner))
	decodedOwner, err := base64.StdEncoding.DecodeString(cleanedOwnerName)
	if err != nil {
		return false, "failed parsing owner name", fmt.Errorf("error decoding owner name: %w", err)
	}
	err = json.Unmarshal(token, &wt)
	if err != nil {
		return false, "token could not be unmarshalled", fmt.Errorf("error unmarshalling token: %w", err)
	}
	subtle := webcrypto.Subtle()
	key, err := subtle.ImportKey(webcrypto.Raw, decodedOwner, wt.Algorithm, false, []webcrypto.KeyUsage{webcrypto.Sign})
	if err != nil {
		return false, "could not import key from path", fmt.Errorf("error importing key: %w", err)
	}
	verify, err := subtle.Verify(wt.Algorithm, key, []byte(wt.Data), []byte(wt.Signature))
	if err != nil {
		return false, "could not verify signature", fmt.Errorf("error verifying signature: %w", err)
	}
	if !verify {
		return false, "signature not valid", nil
	}
	var marshalledTokenData tokenDataJSON
	err = json.Unmarshal([]byte(wt.Data), &marshalledTokenData)
	if err != nil {
		return false, "could not unmarshal token data", fmt.Errorf("error unmarshalling token data: %w", err)
	}
	tokenData, err := marshalledTokenData.Unmarshal()
	if err != nil {
		return false, "could not unmarshal token data", fmt.Errorf("error unmarshalling token data: %w", err)
	}
	now := time.Now()
	if tokenData.ValidBefore.Valid && tokenData.ValidBefore.Time.After(now) {
		return false, "token is no longer valid", nil
	}
	if tokenData.ValidAfter.Valid && tokenData.ValidAfter.Time.Before(now) {
		return false, "token is not yet valid", nil
	}
	if isWriteOp {
		matches := sshUtil.MatchPatternList(tokenData.AllowedWritePaths, path)
		if matches {
			return true, "", nil
		} else {
			return false, "token not allowed on path", nil
		}
	} else {
		matches := sshUtil.MatchPatternList(tokenData.AllowedReadPaths, path)
		if matches {
			return true, "", nil
		} else {
			return false, "token not allowed on path", nil
		}
	}
}

func (s *server) authenticateBiscuitToken(owner *owner, tokenStr, path string, reqType string, isWriteOp bool, clientIP net.IP) (bool, string, error) {
	tokenData, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(tokenStr, "-", "+"), "_", "/"))
	if err != nil {
		return false, "could not decode biscuit token", fmt.Errorf("error decoding biscuit token: %w", err)
	}
	log.Debug("Unmarshalling biscuit token", "tokenData", tokenData, "tokenStr", tokenStr)
	b, err := biscuit.Unmarshal(tokenData)
	if err != nil {
		return false, "could not unmarshal biscuit token", fmt.Errorf("error unmarshalling biscuit token: %w", err)
	}
	unmarshalledOwner, err := base64.StdEncoding.DecodeString(owner.name)
	if err != nil {
		return false, "could not decode biscuit root pubkey", fmt.Errorf("error decoding owner name: %w", err)
	}
	publicRoot := ed25519.PublicKey(unmarshalledOwner)
	authorizer, err := b.Authorizer(publicRoot)
	if err != nil {
		return false, "could not create authorizer", fmt.Errorf("error creating authorizer: %w", err)
	}
	p := parser.New()

	var operationStr string
	if isWriteOp {
		operationStr = "write"
	} else {
		operationStr = "read"
	}

	block, err := p.Block(`
		path({path});
		operation({operation});
	    time({time});
		req_type({req_type});
		client_ip({client_ip});
	`, map[string]biscuit.Term{
		"path":      biscuit.String(path),
		"operation": biscuit.String(operationStr),
		"req_type":  biscuit.String(reqType),
		"time":      biscuit.Date(time.Now().UTC()),
		"client_ip": biscuit.String(clientIP.String())})

	authorizer.AddBlock(block)

	if err := authorizer.Authorize(); err != nil {
		return false, "could not authorize token", fmt.Errorf("error authorizing token: %w", err)
	} else {
		return true, "", nil
	}
}

func (s *server) authenticateToken(owner *owner, tokenStr, path, reqType string, isWriteOp bool, clientIP net.IP) (bool, string, error) {
	s.logger.Debug("Authenticating token", "owner", owner, "tokenStr", tokenStr, "path", path, "isWriteOp", isWriteOp)
	switch owner.typ {
	case ownerTypeBiscuit:
		return s.authenticateBiscuitToken(owner, tokenStr, path, reqType, isWriteOp, clientIP)
	}
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
		return s.authenticateWebcryptoToken(owner.name, decodedToken, path, isWriteOp)
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
	var marshalledTokenData tokenDataJSON
	err = json.Unmarshal([]byte(t.Data), &marshalledTokenData)
	if err != nil {
		return false, "tokenData could not be marshalled", fmt.Errorf("error unmarshalling token data: %w", err)
	}
	tokenData, err := marshalledTokenData.Unmarshal()
	now := time.Now()
	if tokenData.ValidBefore.Valid && tokenData.ValidBefore.Time.After(now) {
		return false, "token is no longer valid", nil
	}
	if tokenData.ValidAfter.Valid && tokenData.ValidAfter.Time.Before(now) {
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
			s.logger.Debug("Key is not signed by owner", "signerFingerprint", signerFingerprint, "owner.typ", owner.typ, "owner.name", owner.name)
			return false, "token not signed by key for namespace", nil
		}
		if isWriteOp {
			matches := sshUtil.MatchPatternList(tokenData.AllowedWritePaths, path)
			if matches {
				return true, "", nil
			} else {
				return false, "token not allowed on path", nil
			}
		} else {
			matches := sshUtil.MatchPatternList(tokenData.AllowedReadPaths, path)
			if matches {
				return true, "", nil
			} else {
				return false, "token not allowed on path", nil
			}
		}
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
				if isWriteOp {
					matches := sshUtil.MatchPatternList(tokenData.AllowedWritePaths, path)
					if matches {
						return true, "", nil
					} else {
						return false, "token not allowed on path", nil
					}
				} else {
					matches := sshUtil.MatchPatternList(tokenData.AllowedReadPaths, path)
					if matches {
						return true, "", nil
					} else {
						return false, "token not allowed on path", nil
					}
				}
			}
		}
		return false, "token not allowed on path", nil
	case ownerTypeGistID:
		allowedSigners, err := s.githubFetchGistAllowedSigners(owner.name)
		if err != nil {
			return false, "could not fetch allowed signers gist", fmt.Errorf("error fetching allowed signers gist: %w", err)
		}
		mk := key.Marshal()
		allowedKeyPresent := false
		for _, allowedKey := range allowedSigners {
			if bytes.Equal(mk, allowedKey.Key.Marshal()) {
				allowedKeyPresent = sshUtil.MatchPatternList(allowedKey.Namespaces, path)
				break
			}
		}
		if !allowedKeyPresent {
			return false, "key not present or allowed in path in allowed_signers", nil
		}
		if isWriteOp {
			matches := sshUtil.MatchPatternList(tokenData.AllowedWritePaths, path)
			if matches {
				return true, "", nil
			} else {
				return false, "token not allowed on path", nil
			}
		} else {
			matches := sshUtil.MatchPatternList(tokenData.AllowedReadPaths, path)
			if matches {
				return true, "", nil
			} else {
				return false, "token not allowed on path", nil
			}
		}
	default:
		return false, "internal error", errors.New("unknown owner type")
	}
}

func compareStringPointerAndString(ptr *string, str string) bool {
	if ptr == nil {
		return false
	}
	return *ptr == str
}

func (s *server) githubFetchGistAllowedSigners(gistID string) ([]sshUtil.AllowedSigner, error) {
	s.gistCacheMutex.RLock()
	if entry, ok := s.gistCache[gistID]; ok {
		if time.Now().Before(entry.ttl) {
			s.gistCacheMutex.RUnlock()
			return entry.allowedSigners, nil
		}
	}
	s.gistCacheMutex.RUnlock()

	gist, _, err := s.githubClient.Gists.Get(s.ctx, gistID)
	if err != nil {
		return nil, fmt.Errorf("failed fetching gist: %w", err)
	}
	if _, exists := gist.Files["allowed_signers"]; !exists {
		return nil, fmt.Errorf("gist does not include an allowed_signers file")
	}
	if _, exists := gist.Files["namespace"]; !exists {
		return nil, fmt.Errorf("gist does not include a namespace file")
	}
	if !compareStringPointerAndString(gist.Files["namespace"].Content, "patch.tionis.dev") {
		return nil, fmt.Errorf("gist namespace does not match (\"%s\" != \"patch.tionis.dev\")", *gist.Files["namespace"].Content)
	}
	if gist.Files["allowed_signers"].Content == nil {
		return nil, fmt.Errorf("gist content is nil")
	}
	gistBytes := []byte(*gist.Files["allowed_signers"].Content)

	signers, err := sshUtil.ParseAllowedSigners(gistBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing allowed signers: %w", err)
	}
	s.gistCacheMutex.Lock()
	s.gistCache[gistID] = gistEntry{
		allowedSigners: signers,
		ttl:            time.Now().Add(githubGistCacheTTL),
	}
	s.gistCacheMutex.Unlock()
	return signers, nil
}
