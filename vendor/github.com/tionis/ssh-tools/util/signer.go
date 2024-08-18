package util

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"os"
)

func GetSignerFromFile(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	key, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}
	return key, nil
}

func getAgent() (agent.Agent, error) {
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}
	agentConn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to agent: %w", err)
	}
	agentClient := agent.NewClient(agentConn)
	return agentClient, nil
}

func GetDefaultSigner() (ssh.Signer, error) {
	ag, err := getAgent()
	if err == nil {
		signers, err := ag.Signers()
		if err != nil {
			return nil, fmt.Errorf("failed to get agent signers: %w", err)
		}
		if len(signers) > 0 {
			return signers[0], nil
		}
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home dir: %w", err)
	}
	var defaultPaths = []string{
		dir + "/.ssh/id_ed25519",
		dir + "/.ssh/id_ecdsa",
		dir + "/.ssh/id_rsa",
		dir + "/.ssh/id_dsa",
		dir + "/.ssh/id_ecdsa_sk",
		dir + "/.ssh/id_ed25519_sk",
	}
	for _, path := range defaultPaths {
		signer, err := GetSignerFromFile(path)
		if err == nil {
			return signer, nil
		}
	}
	return nil, fmt.Errorf("failed to find default signer")
}
