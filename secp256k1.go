package twoecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

type PrivateKey struct {
	ecdsa.PublicKey
	D *big.Int
}

func Rand(c elliptic.Curve) *big.Int {
	n := c.Params().N
	for {
		k, _ := rand.Int(rand.Reader, big.NewInt(1000000000000000000))
		if k.Sign() != 0 && k.Cmp(n) < 0 {
			return k
		}
	}
}

func GenPrivate() *PrivateKey {
	priv := new(PrivateKey)
	priv.PublicKey.Curve = crypto.S256()
	priv.D = Rand(priv.Curve)

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(priv.D.Bytes())

	return priv
}
func (s *PrivateKey) ECDSA() *ecdsa.PrivateKey {
	if s == nil {
		return nil
	}
	b := math.PaddedBigBytes(s.D, s.Params().BitSize/8)
	p, _ := crypto.ToECDSA(b)
	return p
}
