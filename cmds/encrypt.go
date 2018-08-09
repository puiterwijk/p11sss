package cmds

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math"

	sss "github.com/SSSaaS/sssa-golang"
)

func Encrypt(threshold int, text []byte, targets []*rsa.PublicKey) (res [][][]byte, err error) {
	var shares []string
	shares, err = sss.Create(threshold, len(targets), string(text))
	if err != nil {
		return
	}

	res = make([][][]byte, len(targets))
	for i := 0; i < len(targets); i++ {
		key := targets[i]
		//  The message must be no longer than the length of the public modulus
		// minus twice the hash length, minus a further 2.
		partSize := (key.N.BitLen() / 8) - (2 * sha256.Size) - 2
		share := []byte(shares[i])
		numParts := int(math.Ceil(float64(len(share)) / float64(partSize)))

		res[i] = make([][]byte, numParts)

		for j := 0; j < numParts; j++ {
			block := share[partSize*j : partSize*(j+1)]

			var part []byte
			part, err = rsa.EncryptOAEP(
				sha256.New(),
				rand.Reader,
				key,
				block,
				nil,
			)

			if err != nil {
				return
			}

			res[i][j] = part
		}
	}

	return
}
