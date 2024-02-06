package twoecdsa

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

var hash = crypto.Keccak256([]byte("foo"))

func Test_Lindell_add(t *testing.T) {
	p1 := NewParty()
	p2 := NewParty()
	//
	request := p1.Request()

	///
	r := p2.Ref(request)
	signParty := p2.SignParty(hash)
	//
	sign := p1.Sign(hash, signParty, r)
	///
	pubkey := p2.PubKey()
	///
	k := crypto.FromECDSAPub(pubkey)
	if !crypto.VerifySignature(k, hash, sign) {
		t.Fatal("verfiy fatal")
	}
}
