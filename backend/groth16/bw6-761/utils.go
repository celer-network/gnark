package groth16

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bw6761"
	"github.com/ingonyama-zk/iciclegnark/curves/bw6761"
)

func G1ProjectivePointToGnarkJac(p *icicle.G1ProjectivePoint) *bw6761.G1Jac {
	var p1 bw6761.G1Jac
	p1.FromAffine(ProjectiveToGnarkAffine(p))

	return &p1
}

func ProjectiveToGnarkAffine(p *icicle.G1ProjectivePoint) *bw6761.G1Affine {
	px := BaseFieldToGnarkFp(&p.X)
	py := BaseFieldToGnarkFp(&p.Y)
	pz := BaseFieldToGnarkFp(&p.Z)

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(pz)

	x.Mul(px, zInv)
	y.Mul(py, zInv)

	return &bw6761.G1Affine{X: *x, Y: *y}
}

func G2PointToGnarkJac(p *icicle.G2Point) *bw6761.G2Jac {
	x := ToGnarkE2(&p.X)
	y := ToGnarkE2(&p.Y)
	z := ToGnarkE2(&p.Z)
	var zSquared bw6761.E2
	zSquared.Mul(&z, &z)

	var X bw6761.E2
	X.Mul(&x, &z)

	var Y bw6761.E2
	Y.Mul(&y, &zSquared)

	after := bw6761.G2Jac{
		X: X,
		Y: Y,
		Z: z,
	}

	return &after
}

func ToGnarkE2(f *icicle.ExtentionField) bw6761.E2 {
	return bw6761.E2{
		A0: *ToGnarkFp(&f.A0),
		A1: *ToGnarkFp(&f.A1),
	}
}

func ToGnarkFp(f *icicle.G2Element) *fp.Element {
	fb := f.ToBytesLe()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := ElementWithOutConvertingToMontgomery(&b32) // cuda returns montgomery format
	//v2, e := fp.LittleEndian.Element(&b32) // TODO: revert back to this once cuda code is fixed.

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func BaseFieldToGnarkFp(f *icicle.G1BaseField) *fp.Element {
	fb := f.ToBytesLe()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := fp.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

/*
TODO: the following functions are due to a bug in the cuda code,
these fucntions should be deleted once cuda MsmG2 returns non montgomery format
*/
const (
	q0 uint64 = 4332616871279656263
	q1 uint64 = 10917124144477883021
	q2 uint64 = 13281191951274694749
	q3 uint64 = 3486998266802970665
)

func smallerThanModulus(z fp.Element) bool {
	return (z[3] < q3 || (z[3] == q3 && (z[2] < q2 || (z[2] == q2 && (z[1] < q1 || (z[1] == q1 && (z[0] < q0)))))))
}

func ElementWithOutConvertingToMontgomery(b *[32]byte) (fp.Element, error) {
	var z fp.Element
	z[0] = binary.LittleEndian.Uint64((*b)[0:8])
	z[1] = binary.LittleEndian.Uint64((*b)[8:16])
	z[2] = binary.LittleEndian.Uint64((*b)[16:24])
	z[3] = binary.LittleEndian.Uint64((*b)[24:32])

	if !smallerThanModulus(z) {
		return fp.Element{}, errors.New("invalid fp.Element encoding")
	}

	return z, nil
}
