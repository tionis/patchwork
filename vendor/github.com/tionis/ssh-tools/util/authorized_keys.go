package util

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strings"
	"time"
)

// AuthorizedKey represents an SSH authorized_keys entry
type AuthorizedKey struct {
	Key             ssh.PublicKey
	Comment         string
	Principals      []string
	IsCA            bool
	Command         sql.NullString
	Environment     map[string]string
	ExpiryTime      sql.NullTime
	AgentForwarding bool
	From            []*Pattern
	PortForwarding  bool
	Pty             bool
	UserRC          bool
	X11Forwarding   bool
	PermitListen    sql.NullString
	PermitOpen      sql.NullString
	NoTouchReq      bool
	VerifyReq       bool
	Tunnel          sql.NullString
}

func (k *AuthorizedKey) MatchesPrincipal(input string) bool {
	for _, p := range k.Principals {
		if p == input {
			return true
		}
	}
	return false
}

func NewAuthorizedKey(key ssh.PublicKey, comment string, options []string) (*AuthorizedKey, error) {
	ak := &AuthorizedKey{
		Key:        key,
		Comment:    comment,
		Principals: []string{},
		IsCA:       false,
		Command: sql.NullString{
			String: "",
			Valid:  false,
		},
		Environment: map[string]string{},
		ExpiryTime: sql.NullTime{
			Time:  time.Time{},
			Valid: false,
		},
		AgentForwarding: true,
		From:            []*Pattern{},
		PortForwarding:  true,
		Pty:             true,
		UserRC:          true,
		X11Forwarding:   true,
		PermitListen: sql.NullString{
			String: "",
			Valid:  false,
		},
		PermitOpen: sql.NullString{
			String: "",
			Valid:  false,
		},
		NoTouchReq: false,
		VerifyReq:  false,
		Tunnel: sql.NullString{
			String: "",
			Valid:  false,
		},
	}
	for _, option := range options {
		switch option {
		case "agent-forwarding":
			ak.AgentForwarding = true
		case "cert-authority":
			ak.IsCA = true
		case "no-agent-forwarding":
			ak.AgentForwarding = false
		case "no-port-forwarding":
			ak.PortForwarding = false
		case "no-pty":
			ak.Pty = false
		case "no-user-rc":
			ak.UserRC = false
		case "no-x11-forwarding":
			ak.X11Forwarding = false
		case "port-forwarding":
			ak.PortForwarding = true
		case "pty":
			ak.Pty = true
		case "no-touch-required":
			ak.NoTouchReq = true
		case "verify-required":
			ak.VerifyReq = true
		case "user-rc":
			ak.UserRC = true
		case "X11-forwarding":
			ak.X11Forwarding = true
		case "restrict":
			ak.AgentForwarding = false
			ak.PortForwarding = false
			ak.Pty = false
			ak.UserRC = false
			ak.X11Forwarding = false
		default:
			parts := strings.SplitN(option, "=", 2)
			if len(parts) == 2 {
				command := parts[0]
				value := parts[1]
				if value[0] == '"' && value[len(value)-1] == '"' {
					value = value[1 : len(value)-1] // remove quotes if present
				}
				switch command {
				case "command":
					ak.Command.Valid = true
					ak.Command.String = value
				case "environment":
					envParts := strings.SplitN(value, "=", 2)
					if len(envParts) == 2 {
						ak.Environment[envParts[0]] = envParts[1]
					} else {
						return nil, fmt.Errorf("invalid environment option: %s", value)
					}
				case "expiry-time":
					timespec, err := ParseSSHTimespec(value)
					if err != nil {
						return nil, fmt.Errorf("invalid expiry-time: %s", value)
					}
					ak.ExpiryTime.Valid = true
					ak.ExpiryTime.Time = timespec
				case "from":
					parts := strings.Split(value, ",") // ssh_config man page doesn't specify escaping rules, so we'll just split on commas
					for _, part := range parts {
						pattern, err := NewPattern(part)
						if err != nil {
							return nil, fmt.Errorf("invalid from option: %s", value)
						}
						ak.From = append(ak.From, pattern)

					}
				case "permit-listen":
					ak.PermitListen.Valid = true
					ak.PermitListen.String = value
				case "permit-open":
					ak.PermitOpen.Valid = true
					ak.PermitOpen.String = value
				case "principal":
					parts := strings.Split(value, ",") // ssh_config man page doesn't specify escaping rules, so we'll just split on commas
					ak.Principals = append(ak.Principals, parts...)
				case "tunnel":
					ak.Tunnel.Valid = true
					ak.Tunnel.String = value
				default:
					return nil, fmt.Errorf("unknown option: %s", option)
				}
			} else {
				return nil, fmt.Errorf("unknown option: %s", option)
			}
		}
	}
	return ak, nil
}
