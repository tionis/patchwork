package util

import "golang.org/x/crypto/ssh"

func ParseAuthorizedKeys(b []byte) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for len(b) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return nil, err
		}
		keys = append(keys, pubKey)
		b = rest
	}
	return keys, nil
}
