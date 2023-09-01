package groth16

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

type G2Element [4]uint64

type ExtentionField struct {
	A0, A1 G2Element
}

type G2PointAffine struct {
	x, y ExtentionField
}

func (g *G2PointAffine) FromGnarkAffine(gnark *bn254.G2Affine) *G2PointAffine {
	g.x.A0 = gnark.X.A0.Bits()
	g.x.A1 = gnark.X.A1.Bits()
	g.y.A0 = gnark.Y.A0.Bits()
	g.y.A1 = gnark.Y.A1.Bits()

	return g
}

func BatchConvertFromG2Affine(elements []bn254.G2Affine) []G2PointAffine {
	var newElements []G2PointAffine
	for _, gg2Affine := range elements {
		var newElement G2PointAffine
		newElement.FromGnarkAffine(&gg2Affine)

		newElements = append(newElements, newElement)
	}
	return newElements
}

type G2Point struct {
	x, y, z ExtentionField
}

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

func (f *G2Element) toBytesLe() []byte {
	var bytes []byte
	for _, val := range f {
		buf := make([]byte, 8) // 8 bytes because uint64 is 64-bit
		binary.LittleEndian.PutUint64(buf, val)
		bytes = append(bytes, buf...)
	}
	return bytes
}

func (f *G2Element) toGnarkFp() *fp.Element {
	fb := f.toBytesLe()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := ElementWithOutConvertingToMontgomery(&b32) // cuda returns montgomery format
	//v2, e := fp.LittleEndian.Element(&b32) // TODO: revert back to this once cuda code is fixed.

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func (f *ExtentionField) toGnarkE2() bn254.E2 {
	return bn254.E2{
		A0: *f.A0.toGnarkFp(),
		A1: *f.A1.toGnarkFp(),
	}
}

func (p *G2Point) ToGnarkJac() *bn254.G2Jac {
	x := p.x.toGnarkE2()
	y := p.y.toGnarkE2()
	z := p.z.toGnarkE2()

	var zSquared bn254.E2
	zSquared.Mul(&z, &z)

	var X bn254.E2
	X.Mul(&x, &z)

	var Y bn254.E2
	Y.Mul(&y, &zSquared)

	after := bn254.G2Jac{
		X: X,
		Y: Y,
		Z: z,
	}

	return &after
}
