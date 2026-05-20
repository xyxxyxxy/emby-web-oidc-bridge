package password

import (
	"crypto/rand"
	"math/big"
)

const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

// Generate returns a random 8-character password consisting of [a-z0-9].
func Generate() string {
	b := make([]byte, 8)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}
