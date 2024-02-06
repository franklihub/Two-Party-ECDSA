package twoecdsa

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tronch0/crypt0/paillier"
)

func AddCipher(publicKey *paillier.PublicKey, c1, c2 []byte) []byte {
	m1 := new(big.Int).SetBytes(c1)
	m2 := new(big.Int).SetBytes(c2)
	additionRes := new(big.Int).Mul(m1, m2)
	res := new(big.Int).Mod(additionRes, publicKey.NN)
	return res.Bytes()
}

func DecodeSignature(sig []byte) (r, s, v *big.Int) {
	if len(sig) != crypto.SignatureLength {
		panic(fmt.Sprintf("wrong size for signature: got %d, want %d", len(sig), crypto.SignatureLength))
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v
}
func RecoverPlain(R, S, Vb *big.Int, homestead bool) []byte {
	if Vb.BitLen() > 8 {
		return nil
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, homestead) {
		return nil
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	return sig
}
