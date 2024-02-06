package twoecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

func GroupsR(curve elliptic.Curve, k1, k2 *big.Int) *big.Int {

	////s1.D
	r, _ := calGroups(curve, k1, k2)
	return r
}
func GroupsK(curve elliptic.Curve, r1, r2 *big.Int) *big.Int {
	return new(big.Int).Mul(r1, r2)
}
func GroupsX(curve elliptic.Curve, s1, s2 *big.Int) *big.Int {
	return new(big.Int).Mul(s1, s2)
}

// //Q=(x1*x2)*G = G*x1*x2
func GroupsQ(s1, s2 *PrivateKey) *ecdsa.PublicKey {
	x, y := calGroups(s1.Curve, s1.D, s2.D)
	return &ecdsa.PublicKey{Curve: s1.Curve, X: x, Y: y}
}

// Q=x*G = (x1+x2)*G = Q1+Q2
func GroupsQAdd(s1, s2 *PrivateKey) *ecdsa.PublicKey {
	x, y := calGroupsAdd(s1.Curve, s1.D, s2.D)
	return &ecdsa.PublicKey{Curve: s1.Curve, X: x, Y: y}
}

// Q=x*G = (x1+x2)*G = x1*G + x2*G
func calGroupsAdd(curve elliptic.Curve, s1, s2 *big.Int) (*big.Int, *big.Int) {
	//q
	q1X, q1Y := curve.ScalarBaseMult(s1.Bytes())
	q2X, q2Y := curve.ScalarBaseMult(s2.Bytes())
	///
	// Q1x, Q1y := curve.ScalarMult(q1X, q1Y, s1.Bytes())
	// Q2x, Q2y := curve.ScalarMult(q2X, q2Y, s2.Bytes())
	///
	x, y := curve.Add(q1X, q1Y, q2X, q2Y)
	return x, y
}

// //Q=(x1*x2)*G = G*x1*x2
func calGroups(curve elliptic.Curve, s1, s2 *big.Int) (*big.Int, *big.Int) {
	//q
	///
	q1X, q1Y := curve.ScalarBaseMult(s1.Bytes())
	q2X, q2Y := curve.ScalarBaseMult(s2.Bytes())
	///
	Q1X, Q1Y := curve.ScalarMult(q1X, q1Y, s2.Bytes())
	///
	Q2X, Q2Y := curve.ScalarMult(q2X, q2Y, s1.Bytes())
	fmt.Println(Q1X, Q1Y)
	fmt.Println(Q2X, Q2Y)
	//r
	//
	return Q1X, Q1Y
}
