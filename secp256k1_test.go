package twoecdsa

import (
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func Test_compress(t *testing.T) {
	prv := GenPrivate()
	compress := crypto.CompressPubkey(&prv.ECDSA().PublicKey)

	uncompressed, err := crypto.DecompressPubkey(compress)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(prv.ECDSA().PublicKey, *uncompressed) {
		t.Fatalf("keys not equal")
	}
}

func Test_transfer(t *testing.T) {
	prv := GenPrivate()
	key := crypto.FromECDSA(prv.ECDSA())
	priv, err := crypto.ToECDSA(key)
	if err != nil {
		t.Fatal(err)
	}
	///
	sign, err := crypto.Sign(hash, priv)
	if err != nil {
		t.Fatal(err)
	}
	sign = sign[:len(sign)-1]
	k := crypto.FromECDSAPub(&priv.PublicKey)
	if !crypto.VerifySignature(k, hash, sign) {
		t.Fatal("verfiy fatal")
	}
}
