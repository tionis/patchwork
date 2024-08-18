package util

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
)

type knownHost struct {
	marker  string
	pubkey  ssh.PublicKey
	comment string
}

func parseKnownHostsFile(path string) (map[string]knownHost, error) {
	knownHostBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hosts := make(map[string]knownHost)
	for {
		var marker, comment string
		var hostsNames []string
		var pubkey ssh.PublicKey
		marker, hostsNames, pubkey, comment, knownHostBytes, err = ssh.ParseKnownHosts(knownHostBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		for _, host := range hostsNames {
			hosts[host] = knownHost{
				marker:  marker,
				pubkey:  pubkey,
				comment: comment,
			}
		}
	}
	return hosts, nil
}
