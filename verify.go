package twoecdsa

import (
	"crypto/ecdsa"
	"math/big"
)

// /
func Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N
	////
	z := hashToInt(hash, c)
	sInv := new(big.Int).ModInverse(s, N)
	///
	u1 := z.Mul(z, sInv)
	u1.Mod(u1, N)

	u2 := sInv.Mul(r, sInv)
	u2.Mod(u2, N)
	//
	x1, y1 := c.ScalarBaseMult(u1.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())
	x, _ := c.Add(x1, y1, x2, y2)
	x = x.Mod(x, N)
	return x.Cmp(r) == 0
}
