package sw_bw6761

import (
	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type g1constantScalarMul struct {
	A G1Affine
	C G1Affine `gnark:",public"`
	R *big.Int
}

func (circuit *g1constantScalarMul) Define(api frontend.API) error {
	expected := G1Affine{}
	pairing, _ := NewPairing(api)
	expected.ConstantScalarMul(pairing, &circuit.A, circuit.R)
	pairing.Fp.AssertIsEqual(&circuit.C.X, &expected.X)
	pairing.Fp.AssertIsEqual(&circuit.C.Y, &expected.Y)

	return nil
}

func TestConstantScalarMulG1(t *testing.T) {
	_a := randomPointG1()
	var a, c bw6761.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witnesss g1constantScalarMul

	//assign the inputs
	witnesss.A = NewG1Affine(a)

	br, _ := new(big.Int).SetString("137937633822650178050763875402483429610", 10)

	circuit.R = br
	_a.ScalarMultiplication(&_a, br)
	c.FromJacobian(&_a)
	witnesss.C = NewG1Affine(c)

	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witnesss, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func randomPointG1() bw6761.G1Jac {
	p1, _, _, _ := bw6761.Generators()
	var r1 fr.Element
	var b big.Int
	_, _ = r1.SetRandom()
	p1.ScalarMultiplication(&p1, r1.BigInt(&b))
	return p1
}

type varScalarMul struct {
	A G1Affine
	S frontend.Variable
	C G1Affine
}

func (circuit *varScalarMul) Define(api frontend.API) error {
	c := circuit.A.VarScalarMul(api, circuit.A, circuit.S)
	pr, _ := NewPairing(api)
	pr.Fp.AssertIsEqual(&c.X, &circuit.C.X)
	pr.Fp.AssertIsEqual(&c.Y, &circuit.C.Y)
	return nil
}

func TestVarScalarMul(t *testing.T) {
	_a := randomPointG1()
	var a, c bw6761.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witnesss varScalarMul
	witnesss.A = NewG1Affine(a)
	_s, _ := new(big.Int).SetString("137937633822650178050763875402483429610", 10)
	witnesss.S = _s

	_a.ScalarMultiplication(&_a, _s)
	c.FromJacobian(&_a)
	witnesss.C = NewG1Affine(c)

	err := test.IsSolved(&circuit, &witnesss, ecc.BN254.ScalarField())

	asset := test.NewAssert(t)
	asset.NoError(err)

}

type g1DoubleAndAddAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1DoubleAndAddAffine) Define(api frontend.API) error {
	expected := circuit.A
	pairing, _ := NewPairing(api)
	expected.DoubleAndAdd(pairing, &circuit.A, &circuit.B)
	pairing.Fp.AssertIsEqual(&expected.X, &circuit.C.X)
	pairing.Fp.AssertIsEqual(&expected.Y, &circuit.C.Y)

	return nil
}

func TestDoubleAndAddAffineG1(t *testing.T) {

	// sample 2 random points
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c bw6761.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g1DoubleAndAddAffine

	// assign the inputs
	witness.A = NewG1Affine(a)
	witness.B = NewG1Affine(b)

	// compute the result
	_a.Double(&_a).AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C = NewG1Affine(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

}

type ScalarMulTest struct {
	P, Q sw_emulated.AffinePoint[emulated.BW6761Fp]
	S    emulated.Element[emulated.BW6761Fp]
}

func (c *ScalarMulTest) Define(api frontend.API) error {
	cr, err := sw_emulated.New[emulated.BW6761Fp, emulated.BW6761Fp](api, sw_emulated.GetCurveParams[emulated.BW6761Fp]())
	if err != nil {
		return err
	}
	res := cr.ScalarMul(&c.P, &c.S)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	_g, _, _, _ := bw6761.Generators()
	var r fr.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var S bw6761.G1Affine

	var g bw6761.G1Affine
	g.FromJacobian(&_g)
	S.ScalarMultiplication(&g, s)

	circuit := ScalarMulTest{}
	witness := ScalarMulTest{
		S: emulated.ValueOf[emulated.BW6761Fp](s),
		P: sw_emulated.AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](g.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](g.Y),
		},
		Q: sw_emulated.AffinePoint[emulated.BW6761Fp]{
			X: emulated.ValueOf[emulated.BW6761Fp](S.X),
			Y: emulated.ValueOf[emulated.BW6761Fp](S.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type AffineAddAssignTest struct {
	P G1Affine
	Q G1Affine
	C G1Affine
}

func (c *AffineAddAssignTest) Define(api frontend.API) error {
	pr, _ := NewPairing(api)
	c.P.AddAssign(pr, c.Q)
	pr.Fp.AssertIsEqual(&c.P.X, &c.C.X)
	pr.Fp.AssertIsEqual(&c.P.Y, &c.C.Y)
	return nil
}

func TestAffineAddAssign(t *testing.T) {
	var _p = randomPointG1()
	var _q = randomPointG1()

	var p, q, c bw6761.G1Affine
	p.FromJacobian(&_p)
	q.FromJacobian(&_q)

	_p.AddAssign(&_q)

	c.FromJacobian(&_p)
	witness := AffineAddAssignTest{
		P: NewG1Affine(p),
		Q: NewG1Affine(q),
		C: NewG1Affine(c),
	}

	assert := test.NewAssert(t)
	err := test.IsSolved(&AffineAddAssignTest{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}
