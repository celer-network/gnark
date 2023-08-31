package groth16

import (
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const SCALAR_SIZE = 8
const BASE_SIZE = 8

type ScalarField struct {
	s [SCALAR_SIZE]uint32
}

type BaseField struct {
	s [BASE_SIZE]uint32
}

type Field interface {
	toGnarkFr() *fr.Element
}

func BatchConvertFromFrGnark[T BaseField | ScalarField](elements []fr.Element) []T {
	var newElements []T
	for _, e := range elements {
		converted := NewFieldFromFrGnark[T](e)
		newElements = append(newElements, *converted)
	}

	return newElements
}
func NewFieldFromFrGnark[T BaseField | ScalarField](element fr.Element) *T {
	s := ConvertUint64ArrToUint32Arr(element.Bits()) // get non-montgomry

	return &T{s}
}

func ConvertUint64ArrToUint32Arr(arr64 [4]uint64) [8]uint32 {
	var arr32 [8]uint32
	for i, v := range arr64 {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)

		arr32[i*2] = binary.LittleEndian.Uint32(b[0:4])
		arr32[i*2+1] = binary.LittleEndian.Uint32(b[4:8])
	}

	return arr32
}

type PointAffineNoInfinityBN254 struct {
	x, y BaseField
}

type PointBN254 struct {
	x, y, z BaseField
}

func NewFieldFromFpGnark[T BaseField | ScalarField](element fp.Element) *T {
	s := ConvertUint64ArrToUint32Arr(element.Bits()) // get non-montgomry

	return &T{s}
}

func NewBaseFieldOne() *BaseField {
	var s [BASE_SIZE]uint32

	s[0] = 1

	return &BaseField{s}
}

func PointBN254FromG1AffineGnark(gnark *bn254.G1Affine) *PointBN254 {
	point := PointBN254{
		x: *NewFieldFromFpGnark[BaseField](gnark.X),
		y: *NewFieldFromFpGnark[BaseField](gnark.Y),
		z: *NewBaseFieldOne(),
	}

	return &point
}

func (p *PointBN254) strip_z() *PointAffineNoInfinityBN254 {
	return &PointAffineNoInfinityBN254{
		x: p.x,
		y: p.y,
	}
}

func (p *PointBN254) ToGnarkJac() *bn254.G1Jac {
	var p1 bn254.G1Jac
	p1.FromAffine(p.toGnarkAffine())

	return &p1
}

func (p *PointBN254) toGnarkAffine() *bn254.G1Affine {
	px := p.x.toGnarkFp()
	py := p.y.toGnarkFp()
	pz := p.z.toGnarkFp()

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(pz)

	x.Mul(px, zInv)
	y.Mul(py, zInv)

	return &bn254.G1Affine{X: *x, Y: *y}
}

func (f *BaseField) toGnarkFp() *fp.Element {
	fb := f.toBytesLe()
	var b32 [32]byte
	copy(b32[:], fb[:32])

	v, e := fp.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to create convert point %v got error %v", f, e))
	}

	return &v
}

func (f *BaseField) toBytesLe() []byte {
	bytes := make([]byte, len(f.s)*4)
	for i, v := range f.s {
		binary.LittleEndian.PutUint32(bytes[i*4:], v)
	}

	return bytes
}

func BatchConvertFromG1Affine(elements []bn254.G1Affine) []PointAffineNoInfinityBN254 {
	var newElements []PointAffineNoInfinityBN254
	for _, e := range elements {
		newElement := PointBN254FromG1AffineGnark(&e).strip_z()
		newElements = append(newElements, *newElement)
	}
	return newElements
}
