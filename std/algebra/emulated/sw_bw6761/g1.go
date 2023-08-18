/*
 *
 * Copyright © 2020 ConsenSys
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package sw_bw6761

import (
	"fmt"
	"github.com/consensys/gnark/constraint/solver"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
)

type G1Affine struct {
	X, Y fields_bw6761.BaseField
}

func NewG1Affine(a bw6761.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[emulated.BW6761Fp](a.X),
		Y: emulated.ValueOf[emulated.BW6761Fp](a.Y),
	}
}

// Neg computes -G
func (p *G1Affine) Neg(pr *Pairing, a *G1Affine) *G1Affine {
	p.X = a.X
	p.Y = *pr.Fp.Neg(&a.Y)
	return p
}

// g1Proj point in projective coordinates
type g1Proj struct {
	x, y, z fields_bw6761.BaseField
}

// Set sets p to the provided point
func (p *g1Proj) Set(a *g1Proj) *g1Proj {
	p.x, p.y, p.z = a.x, a.y, a.z
	return p
}

// Neg computes -G
func (p *g1Proj) Neg(pr *Pairing, a *g1Proj) *g1Proj {
	p.Set(a)
	p.y = *pr.Fp.Neg(&a.y)
	return p
}

// FromAffine sets p = Q, p in homogenous projective, Q in affine
func (p *g1Proj) FromAffine(pr *Pairing, Q *G1Affine) *g1Proj {
	p.z = *pr.Fp.One()
	p.x = Q.X
	p.y = Q.Y
	return p
}

// BatchProjectiveToAffineG1 converts points in Projective coordinates to Affine coordinates
// performing a single field inversion (Montgomery batch inversion trick).
func BatchProjectiveToAffineG1(pr *Pairing, points []g1Proj) []G1Affine {
	result := make([]G1Affine, len(points))
	//zeroes := make([]bool, len(points))
	accumulator := pr.Fp.One()

	// batch invert all points[].Z coordinates with Montgomery batch inversion trick
	// (stores points[].Z^-1 in result[i].X to avoid allocating a slice of fr.Elements)
	for i := 0; i < len(points); i++ {
		//if points[i].z.IsZero() {
		//	zeroes[i] = true
		//	continue
		//}
		result[i].X = *accumulator
		accumulator = pr.Fp.MulMod(accumulator, &points[i].z)
	}

	accInverse := pr.Fp.Inverse(accumulator)

	for i := len(points) - 1; i >= 0; i-- {
		//if zeroes[i] {
		//	// do nothing, (X=0, Y=0) is infinity point in affine
		//	continue
		//}
		result[i].X = *pr.Fp.MulMod(&result[i].X, accInverse)
		accInverse = pr.Fp.MulMod(accInverse, &points[i].z)
	}

	// batch convert to affine.
	for i := 0; i < len(points); i++ {
		//if zeroes[i] {
		//	// do nothing, (X=0, Y=0) is infinity point in affine
		//	continue
		//}
		a := result[i].X
		result[i].X = *pr.Fp.MulMod(&points[i].x, &a)
		result[i].Y = *pr.Fp.MulMod(&points[i].y, &a)
	}
	return result
}

func (p *G1Affine) ConstantScalarMul(pr *Pairing, Q *G1Affine, s *big.Int) *G1Affine {

	var Acc, negQ, negPhiQ, phiQ G1Affine
	s.Mod(s, ecc.BW6_761.ScalarField())
	phi1(pr, &phiQ, Q)
	k := ecc.SplitScalar(s, &glvBasis)
	if k[0].Sign() == -1 {
		k[0].Neg(&k[0])
		Q.Neg(pr, Q)
	}
	if k[1].Sign() == -1 {
		k[1].Neg(&k[1])
		phiQ.Neg(pr, &phiQ)
	}
	nbits := k[0].BitLen()
	if k[1].BitLen() > nbits {
		nbits = k[1].BitLen()
	}
	negQ.Neg(pr, Q)
	negPhiQ.Neg(pr, &phiQ)

	var table [4]G1Affine
	table[0] = negQ
	table[0].AddAssign(pr, negPhiQ)
	table[1] = *Q
	table[1].AddAssign(pr, negPhiQ)
	table[2] = negQ
	table[2].AddAssign(pr, phiQ)
	table[3] = *Q
	table[3].AddAssign(pr, phiQ)

	Acc = table[3]
	// if both high bits are set, then we would get to the incomplete part,
	// handle it separately.
	if k[0].Bit(nbits-1) == 1 && k[1].Bit(nbits-1) == 1 {
		Acc.Double(pr, Acc)
		Acc.AddAssign(pr, table[3])
		nbits = nbits - 1
	}
	for i := nbits - 1; i > 0; i-- {
		fmt.Println("acc i:", i)
		Acc.DoubleAndAdd(pr, &Acc, &table[k[0].Bit(i)+2*k[1].Bit(i)])
	}

	negQ.AddAssign(pr, Acc)
	Acc.Select(pr, k[0].Bit(0), Acc, negQ)
	negPhiQ.AddAssign(pr, Acc)
	Acc.Select(pr, k[1].Bit(0), Acc, negPhiQ)
	p.X, p.Y = Acc.X, Acc.Y

	return p
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (p *G1Affine) Select(pr *Pairing, b frontend.Variable, p1, p2 G1Affine) *G1Affine {
	p.X = *pr.Fp.Select(b, &p1.X, &p2.X)
	p.Y = *pr.Fp.Select(b, &p1.Y, &p2.Y)
	return p

}

// Double double a point in affine coords
func (p *G1Affine) Double(pr *Pairing, p1 G1Affine) *G1Affine {
	ba := pr.Fp

	var three, two big.Int
	three.SetInt64(3)
	two.SetInt64(2)

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	lambdaL := ba.MulConst(ba.Mul(&p1.X, &p1.X), &three)
	lambdaR := ba.MulConst(&p1.Y, &two)
	lambda := ba.Div(lambdaL, lambdaR)

	// xr = lambda**2-p1.x-p1.x
	xr := ba.Sub(ba.Mul(lambda, lambda), ba.MulConst(&p1.X, &two))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = *ba.Sub(ba.Mul(lambda, ba.Sub(&p1.X, xr)), &p1.Y)

	//p.x = xr
	p.X = *xr

	return p
}

// DoubleAndAdd computes 2*p1+p in affine coords
func (p *G1Affine) DoubleAndAdd(pr *Pairing, p1, p2 *G1Affine) *G1Affine {
	ba := pr.Fp

	// compute lambda1 = (y2-y1)/(x2-x1)
	l1 := ba.Div(ba.Sub(&p1.Y, &p2.Y), ba.Sub(&p1.X, &p2.X))

	// compute x3 = lambda1**2-x1-x2
	x3 := ba.MulMod(l1, l1)
	x3 = ba.Sub(x3, &p1.X)
	x3 = ba.Sub(x3, &p2.X)

	// omit y3 computation
	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	l2 := ba.Div(ba.Add(&p1.Y, &p1.Y), ba.Sub(x3, &p1.X))
	l2 = ba.Add(l2, l1)
	l2 = ba.Neg(l2)

	// compute x4 =lambda2**2-x1-x3
	x4 := ba.MulMod(l2, l2)
	x4 = ba.Sub(x4, &p1.X)
	x4 = ba.Sub(x4, x3)

	// compute y4 = lambda2*(x1 - x4)-y1
	y4 := ba.Sub(&p1.X, x4)
	y4 = ba.Mul(l2, y4)
	y4 = ba.Sub(y4, &p1.Y)

	p.X = *x4
	p.Y = *y4

	return p
}

func phi1(pr *Pairing, res, p *G1Affine) *G1Affine {
	root1 := emulated.ValueOf[emulated.BW6761Fp](thirdRootOneG1)
	res.X = *pr.Fp.Mul(&p.X, &root1)
	res.Y = p.Y
	return res
}

func (p *G1Affine) AddAssign(pr *Pairing, q G1Affine) *G1Affine {
	ba := pr.Fp

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	lambda := ba.Div(ba.Sub(&q.Y, &p.Y), ba.Sub(&q.X, &p.X))

	// xr = lambda**2-p.x-p1.x
	xr := ba.Sub(ba.MulMod(lambda, lambda), ba.Add(&p.X, &q.X))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = *ba.Sub(ba.Mul(lambda, ba.Sub(&p.X, xr)), &p.Y)

	//p.x = xr
	p.X = *xr

	return p

}

func (P *G1Affine) VarScalarMul(api frontend.API, Q G1Affine, s frontend.Variable) *G1Affine {
	sd, err := api.Compiler().NewHint(DecomposeScalarG1, 3, s)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2 := sd[0], sd[1]
	// when we split scalar, then s1, s2 < lambda by default. However, to have
	// the high 1-2 bits of s1, s2 set, the hint functions compute the
	// decomposition for
	//     s + k*r (for some k)
	// instead and omits the last reduction. Thus, to constrain s1 and s2, we
	// have to assert that
	//     s1 + λ * s2 == s + k*r
	api.AssertIsEqual(api.Add(s1, api.Mul(s2, lambdaGLV)), api.Add(s, api.Mul(ecc.BW6_761.ScalarField(), sd[2])))

	nbits := lambdaGLV.BitLen() + 1

	s1bits := api.ToBinary(s1, nbits)
	s2bits := api.ToBinary(s2, nbits)

	pairing, _ := NewPairing(api)

	var Acc /*accumulator*/, B, B2 /*tmp vars*/ G1Affine
	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	tableQ[1] = Q
	tableQ[0].Neg(pairing, &Q)
	phi1(pairing, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(pairing, &tablePhiQ[1])

	// We now initialize the accumulator. Due to the way the scalar is
	// decomposed, either the high bits of s1 or s2 are set and we can use the
	// incomplete addition laws.

	//     Acc = Q + Φ(Q)
	Acc = tableQ[1]
	Acc.AddAssign(pairing, tablePhiQ[1])

	// However, we can not directly add step value conditionally as we may get
	// to incomplete path of the addition formula. We either add or subtract
	// step value from [2] Acc (instead of conditionally adding step value to
	// Acc):
	//     Acc = [2] (Q + Φ(Q)) ± Q ± Φ(Q)
	Acc.Double(pairing, Acc)
	// only y coordinate differs for negation, select on that instead.
	B.X = tableQ[0].X
	B.Y = *pairing.Fp.Select(s1bits[nbits-1], &tableQ[1].Y, &tableQ[0].Y)
	Acc.AddAssign(pairing, B)
	B.X = tablePhiQ[0].X
	B.Y = *pairing.Fp.Select(s2bits[nbits-1], &tablePhiQ[1].Y, &tablePhiQ[0].Y)
	Acc.AddAssign(pairing, B)

	// second bit
	Acc.Double(pairing, Acc)
	B.X = tableQ[0].X
	B.Y = *pairing.Fp.Select(s1bits[nbits-2], &tableQ[1].Y, &tableQ[0].Y)
	Acc.AddAssign(pairing, B)
	B.X = tablePhiQ[0].X
	B.Y = *pairing.Fp.Select(s2bits[nbits-2], &tablePhiQ[1].Y, &tablePhiQ[0].Y)
	Acc.AddAssign(pairing, B)

	B2.X = tablePhiQ[0].X
	for i := nbits - 3; i > 0; i-- {
		B.X = Q.X
		B.Y = *pairing.Fp.Select(s1bits[i], &tableQ[1].Y, &tableQ[0].Y)
		B2.Y = *pairing.Fp.Select(s2bits[i], &tablePhiQ[1].Y, &tablePhiQ[0].Y)
		B.AddAssign(pairing, B2)
		Acc.DoubleAndAdd(pairing, &Acc, &B)
	}

	tableQ[0].AddAssign(pairing, Acc)
	Acc.Select(pairing, s1bits[0], Acc, tableQ[0])
	tablePhiQ[0].AddAssign(pairing, Acc)
	Acc.Select(pairing, s2bits[0], Acc, tablePhiQ[0])

	P.X = Acc.X
	P.Y = Acc.Y

	return P
}

var DecomposeScalarG1 = func(scalarField *big.Int, inputs []*big.Int, res []*big.Int) error {
	sp := ecc.SplitScalar(inputs[0], &glvBasis)
	res[0].Set(&(sp[0]))
	res[1].Set(&(sp[1]))
	one := big.NewInt(1)
	// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
	// the high bits are set in decomposition.
	for res[0].Cmp(&lambdaGLV) < 1 && res[1].Cmp(&lambdaGLV) < 1 {
		res[0].Add(res[0], &lambdaGLV)
		res[0].Add(res[0], one)
		res[1].Add(res[1], &lambdaGLV)
	}
	// figure out how many times we have overflowed
	res[2].Mul(res[1], &lambdaGLV).Add(res[2], res[0])
	res[2].Sub(res[2], inputs[0])
	res[2].Div(res[2], ecc.BW6_761.ScalarField())

	return nil
}

func init() {
	solver.RegisterHint(DecomposeScalarG1)
}
