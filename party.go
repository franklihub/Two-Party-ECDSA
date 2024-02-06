package twoecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/tronch0/crypt0/paillier"
)

type Party struct {
	prv *PrivateKey
	k   *big.Int
	///
	r *big.Int
	///
	reqeust *Request
}
type QParty struct {
	X, Y *big.Int
}
type Request struct {
	X, Y *big.Int
	PKey *paillier.PrivateKey
	Q    *QParty
	E1   []byte
}

func (s *Request) Marshal() ([]byte, error) {
	j, err := json.Marshal(s)
	return j, err
}
func (s *Request) Unmarshal(j []byte) error {
	return json.Unmarshal(j, s)
}

func PartyContext(prv *PrivateKey, k *big.Int) *Party {
	p := &Party{
		prv: prv,
	}
	p.k = k
	return p
}
func NewParty() *Party {
	p := &Party{
		prv: GenPrivate(),
	}
	p.k = Rand(p.prv.Curve)
	return p
}

// /
func (s *Party) Request() *Request {
	pkey, _ := paillier.GenerateKey(rand.Reader)
	///
	x, y := s.prv.Curve.ScalarBaseMult(s.k.Bytes())
	//
	e1, _ := paillier.Encrypt(&pkey.PublicKey, s.prv.D.Bytes())

	//
	rparty := &Request{
		x, y,
		pkey,
		s.qparty(),
		e1,
	}
	s.reqeust = rparty
	return rparty
}

func (s *Party) Ref(r *Request) *big.Int {
	groupsX, _ := s.prv.Curve.ScalarMult(r.X, r.Y, s.k.Bytes())
	s.r = groupsX
	s.reqeust = r
	return s.r
}

// /Q = x * G = (x1 + x2)*G=x1*G + x2*G = Q1+Q2
func (s *Party) qparty() *QParty {
	x, y := s.prv.Curve.ScalarBaseMult(s.prv.D.Bytes())
	return &QParty{x, y}
}
func (s *Party) PubKey() *ecdsa.PublicKey {
	x1, y2 := s.prv.Curve.ScalarBaseMult(s.prv.D.Bytes())
	x, y := s.prv.Curve.Add(s.reqeust.Q.X, s.reqeust.Q.Y, x1, y2)
	return &ecdsa.PublicKey{Curve: s.prv.Curve, X: x, Y: y}
}

// /
// //s = (k1*k2)-1 * (H(m)+r*(x1+x2)) mod q
// /(k2-1 * H(m)+r*k2-1 * (x2 + x1)) * k1-1 mod q
// /
// /E(x1) ->
// c1= E(p q)+k2-1*H(m)
// c2 = E(x2) + E(x1)
// c4 = r*k2-1 * c3
// c5 = c1+c4
// D(c5)*k1-1
func (s *Party) SignParty(hash []byte) []byte {
	k_Inv := new(big.Int).ModInverse(s.k, s.prv.Curve.Params().N)
	e := hashToInt(hash, s.prv.Curve)
	c1 := new(big.Int).Mul(k_Inv, e)
	//
	c2, err := paillier.Encrypt(&s.reqeust.PKey.PublicKey, s.prv.D.Bytes())
	if err != nil {
		fmt.Println(err)
	}
	c3 := AddCipher(&s.reqeust.PKey.PublicKey, s.reqeust.E1, c2)
	///
	b4 := new(big.Int).Mul(s.r, k_Inv)
	c4 := paillier.Mul(&s.reqeust.PKey.PublicKey, c3, b4.Bytes())

	c5, _ := paillier.Add(&s.reqeust.PKey.PublicKey, c4, c1.Bytes())
	if err != nil {
		fmt.Println(err)
	}
	///
	return c5
}
func (s *Party) Sign(hash []byte, c []byte, r *big.Int) []byte {
	k_Inv := new(big.Int).ModInverse(s.k, s.prv.Curve.Params().N)
	d, err := paillier.Decrypt(s.reqeust.PKey, c)
	if err != nil {
		fmt.Println(err)
	}
	ss := new(big.Int).Mul(new(big.Int).SetBytes(d), k_Inv)
	ss = ss.Mod(ss, s.prv.Curve.Params().N)

	sign := RecoverPlain(r, ss, big.NewInt(28), false)
	return sign[:len(sign)-1]
}
