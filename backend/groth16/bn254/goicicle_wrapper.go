package groth16

import (
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cudawrapper "github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
)

type OnDeviceData struct {
	p    unsafe.Pointer
	size int
}

func INttOnDevice(scalars_d, twiddles_d, cosetPowers_d unsafe.Pointer, size int, isCoset bool) (unsafe.Pointer, error) {
	_, err := icicle.ReverseScalars(scalars_d, size)
	if err != nil {
		return nil, err
	}
	// TODO Interpolate do not return error
	scalarsInterp := icicle.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)
	return scalarsInterp, nil
}

func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) (err error) {
	if is_into {
		_, err = icicle.ToMontgomery(scalars_d, size)
	} else {
		_, err = icicle.FromMontgomery(scalars_d, size)
	}
	return
}

func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) error {
	res := icicle.Evaluate(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)
	if res != 0 {
		return fmt.Errorf("evaluate err %d", res)
	}

	_, err := icicle.ReverseScalars(scalars_out, size)
	if err != nil {
		return err
	}
	return nil
}

func PolyOps(a_d, b_d, c_d, den_d unsafe.Pointer, size int) error {
	ret := icicle.VecScalarMulMod(a_d, b_d, size)

	if ret != 0 {
		return fmt.Errorf("PolyOps VecScalarMulMod fail, ret: %d", ret)
	}
	ret = icicle.VecScalarSub(a_d, c_d, size)

	if ret != 0 {
		return fmt.Errorf("VecScalarSub fail, ret: %d", ret)
	}
	ret = icicle.VecScalarMulMod(a_d, den_d, size)

	if ret != 0 {
		return fmt.Errorf("VecScalarMulMod fail, ret: %d", ret)
	}

	return nil
}

func MsmOnDevice(scalars_d, points_d unsafe.Pointer, count, bucketFactor int, convert bool) (*curve.G1Jac, unsafe.Pointer, error, time.Duration) {
	g1ProjPointBytes := fp.Bytes * 3
	out_d, err := cudawrapper.CudaMalloc(g1ProjPointBytes)
	if err != nil {
		return nil, nil, err, time.Second
	}

	defer func() {
		freeRet := cudawrapper.CudaFree(out_d)
		if freeRet != 0 {
			fmt.Println("MsmOnDevice free fail with code", freeRet)
		}
	}()

	msmTime := time.Now()
	if ret := icicle.Commit(out_d, scalars_d, points_d, count, bucketFactor); ret != 0 {
		return nil, nil, fmt.Errorf("MsmOnDevice icicle.Commit fail with code %d", ret), time.Second
	}
	timings := time.Since(msmTime)

	if convert {
		outHost := make([]icicle.G1ProjectivePoint, 1)
		if ret := cudawrapper.CudaMemCpyDtoH[icicle.G1ProjectivePoint](outHost, out_d, g1ProjPointBytes); ret != 0 {
			return nil, nil, fmt.Errorf("MsmOnDevice cpyHRet fail with code %d", ret), time.Second
		}
		retPoint := G1ProjectivePointToGnarkJac(&outHost[0])
		return retPoint, nil, nil, timings
	}

	return nil, out_d, nil, timings
}

func MsmG2OnDevice(scalars_d, points_d unsafe.Pointer, count, bucketFactor int, convert bool) (*curve.G2Jac, unsafe.Pointer, error, time.Duration) {
	g2ProjPointBytes := fp.Bytes * 6
	out_d, err := cudawrapper.CudaMalloc(g2ProjPointBytes)
	if err != nil {
		return nil, nil, err, time.Second
	}

	defer func() {
		if ret := cudawrapper.CudaFree(out_d); ret != 0 {
			fmt.Println("MsmOnDevice free fail with code", ret)
		}
	}()

	msmTime := time.Now()
	if ret := icicle.CommitG2(out_d, scalars_d, points_d, count, bucketFactor); ret != 0 {
		return nil, nil, fmt.Errorf("MsmG2OnDevice icicle.Commit fail with code %d", ret), time.Second
	}
	timings := time.Since(msmTime)

	if convert {
		outHost := make([]icicle.G2Point, 1)
		if ret := cudawrapper.CudaMemCpyDtoH[icicle.G2Point](outHost, out_d, g2ProjPointBytes); ret != 0 {
			return nil, nil, fmt.Errorf("MsmOnDevice cpyHRet fail with code %d", ret), time.Second
		}
		retPoint := G2PointToGnarkJac(&outHost[0])
		return retPoint, nil, nil, timings
	}
	return nil, out_d, nil, timings
}

// TODO, if has error, should free cudaMem?
func CopyToDevice(scalars []fr.Element, bytes int) (unsafe.Pointer, error) {
	devicePtr, cmErr := cudawrapper.CudaMalloc(bytes)
	if cmErr != nil {
		return nil, cmErr
	}
	ret := cudawrapper.CudaMemCpyHtoD[fr.Element](devicePtr, scalars, bytes)
	if ret != 0 {
		return nil, fmt.Errorf("CudaMemCpyHtoD fail with %d", ret)
	}
	err := MontConvOnDevice(devicePtr, len(scalars), false)
	if err != nil {
		return nil, err
	}
	return devicePtr, nil
}

func G1ProjectivePointToGnarkJac(p *icicle.G1ProjectivePoint) *curve.G1Jac {
	var p1 curve.G1Jac
	p1.FromAffine(ProjectiveToGnarkAffine(p))

	return &p1
}

func ProjectiveToGnarkAffine(p *icicle.G1ProjectivePoint) *curve.G1Affine {
	px := BaseFieldToGnarkFp(&p.X)
	py := BaseFieldToGnarkFp(&p.Y)
	pz := BaseFieldToGnarkFp(&p.Z)

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(pz)

	x.Mul(px, zInv)
	y.Mul(py, zInv)

	return &curve.G1Affine{X: *x, Y: *y}
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

func ToGnarkE2(f *icicle.ExtentionField) curve.E2 {
	return curve.E2{
		A0: *ToGnarkFp(&f.A0),
		A1: *ToGnarkFp(&f.A1),
	}
}

func G2PointToGnarkJac(p *icicle.G2Point) *curve.G2Jac {
	x := ToGnarkE2(&p.X)
	y := ToGnarkE2(&p.Y)
	z := ToGnarkE2(&p.Z)
	var zSquared curve.E2
	zSquared.Mul(&z, &z)

	var X curve.E2
	X.Mul(&x, &z)

	var Y curve.E2
	Y.Mul(&y, &zSquared)

	after := curve.G2Jac{
		X: X,
		Y: Y,
		Z: z,
	}

	return &after
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

const (
	q0 uint64 = 4332616871279656263
	q1 uint64 = 10917124144477883021
	q2 uint64 = 13281191951274694749
	q3 uint64 = 3486998266802970665
)

func ElementWithOutConvertingToMontgomery(b *[32]byte) (fp.Element, error) {
	var z fp.Element
	z[0] = binary.LittleEndian.Uint64((*b)[0:8])
	z[1] = binary.LittleEndian.Uint64((*b)[8:16])
	z[2] = binary.LittleEndian.Uint64((*b)[16:24])
	z[3] = binary.LittleEndian.Uint64((*b)[24:32])

	if !smallerThanModulus(z) {
		return fp.Element{}, fmt.Errorf("invalid fp.Element encoding")
	}

	return z, nil
}

func smallerThanModulus(z fp.Element) bool {
	return (z[3] < q3 || (z[3] == q3 && (z[2] < q2 || (z[2] == q2 && (z[1] < q1 || (z[1] == q1 && (z[0] < q0)))))))
}

func NewFieldFromFrGnark[T icicle.G1BaseField | icicle.G1ScalarField](element fr.Element) *T {
	s := icicle.ConvertUint64ArrToUint32Arr(element.Bits()) // get non-montgomry

	return &T{s}
}

func NewFieldFromFpGnark[T icicle.G1BaseField | icicle.G1ScalarField](element fp.Element) *T {
	s := icicle.ConvertUint64ArrToUint32Arr(element.Bits()) // get non-montgomry

	return &T{s}
}

func BatchConvertFromG1Affine(elements []curve.G1Affine) []icicle.G1PointAffine {
	var newElements []icicle.G1PointAffine
	for _, e := range elements {
		var newElement icicle.G1ProjectivePoint
		FromG1AffineGnark(&e, &newElement)

		newElements = append(newElements, *newElement.StripZ())
	}
	return newElements
}

func FromG1AffineGnark(gnark *curve.G1Affine, p *icicle.G1ProjectivePoint) *icicle.G1ProjectivePoint {
	var z icicle.G1BaseField
	z.SetOne()

	p.X = *NewFieldFromFpGnark[icicle.G1BaseField](gnark.X)
	p.Y = *NewFieldFromFpGnark[icicle.G1BaseField](gnark.Y)
	p.Z = z

	return p
}

func BatchConvertFromG2Affine(elements []curve.G2Affine) []icicle.G2PointAffine {
	var newElements []icicle.G2PointAffine
	for _, gg2Affine := range elements {
		var newElement icicle.G2PointAffine
		G2AffineFromGnarkAffine(&gg2Affine, &newElement)

		newElements = append(newElements, newElement)
	}
	return newElements
}

func G2AffineFromGnarkAffine(gnark *curve.G2Affine, g *icicle.G2PointAffine) *icicle.G2PointAffine {
	g.X.A0 = gnark.X.A0.Bits()
	g.X.A1 = gnark.X.A1.Bits()
	g.Y.A0 = gnark.Y.A0.Bits()
	g.Y.A1 = gnark.Y.A1.Bits()

	return g
}
