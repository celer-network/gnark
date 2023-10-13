package groth16

import (
	"fmt"
	"time"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	cudawrapper "github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bw6761"
)

type OnDeviceData struct {
	p    unsafe.Pointer
	size int
}

// func INttOnDevice(scalars_d, twiddles_d, cosetPowers_d unsafe.Pointer, size int, isCoset bool) (unsafe.Pointer, error) {
// 	_, err := icicle.ReverseScalars(scalars_d, size)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// TODO Interpolate do not return error
// 	scalarsInterp := icicle.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)
// 	return scalarsInterp, nil
// }

func INttOnDevice(scalars_d, twiddles_d, cosetPowers_d unsafe.Pointer, size, sizeBytes int, isCoset bool) (unsafe.Pointer, []time.Duration) {
	var timings []time.Duration
	revTime := time.Now()
	_, err := icicle.ReverseScalars(scalars_d, size)
	if err != nil {
		fmt.Println("INttOnDevice err: %d", err)
	}
	revTimeElapsed := time.Since(revTime)
	timings = append(timings, revTimeElapsed)

	interpTime := time.Now()
	scalarsInterp := icicle.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)

	interpTimeElapsed := time.Since(interpTime)
	timings = append(timings, interpTimeElapsed)
	return scalarsInterp, timings
}

func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) (err error) {
	if is_into {
		_, err = icicle.ToMontgomery(scalars_d, size)
	} else {
		_, err = icicle.FromMontgomery(scalars_d, size)
	}
	return
}

// func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) error {
// 	res := icicle.Evaluate(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)
// 	if res != 0 {
// 		return fmt.Errorf("evaluate err %d", res)
// 	}

//		_, err := icicle.ReverseScalars(scalars_out, size)
//		if err != nil {
//			return err
//		}
//		return nil
//	}
func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) []time.Duration {
	var timings []time.Duration
	evalTime := time.Now()
	res := icicle.Evaluate(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)
	evalTimeElapsed := time.Since(evalTime)
	timings = append(timings, evalTimeElapsed)

	if res != 0 {
		fmt.Print("Issue evaluating")
	}

	revTime := time.Now()
	icicle.ReverseScalars(scalars_out, size)
	revTimeElapsed := time.Since(revTime)
	timings = append(timings, revTimeElapsed)

	return timings
}

// func PolyOps(a_d, b_d, c_d, den_d unsafe.Pointer, size int) error {
// 	ret := icicle.VecScalarMulMod(a_d, b_d, size)

// 	if ret != 0 {
// 		return fmt.Errorf("PolyOps VecScalarMulMod fail, ret: %d", ret)
// 	}
// 	ret = icicle.VecScalarSub(a_d, c_d, size)

// 	if ret != 0 {
// 		return fmt.Errorf("VecScalarSub fail, ret: %d", ret)
// 	}
// 	ret = icicle.VecScalarMulMod(a_d, den_d, size)

// 	if ret != 0 {
// 		return fmt.Errorf("VecScalarMulMod fail, ret: %d", ret)
// 	}

//		return nil
//	}
func PolyOps(a_d, b_d, c_d, den_d unsafe.Pointer, size int) (timings []time.Duration) {
	convSTime := time.Now()
	ret := icicle.VecScalarMulMod(a_d, b_d, size)
	timings = append(timings, time.Since(convSTime))

	if ret != 0 {
		fmt.Print("Vector mult a*b issue")
	}
	convSTime = time.Now()
	ret = icicle.VecScalarSub(a_d, c_d, size)
	timings = append(timings, time.Since(convSTime))

	if ret != 0 {
		fmt.Print("Vector sub issue")
	}
	convSTime = time.Now()
	ret = icicle.VecScalarMulMod(a_d, den_d, size)
	timings = append(timings, time.Since(convSTime))

	if ret != 0 {
		fmt.Print("Vector mult a*den issue")
	}

	return
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
	// bw6761, G2 = G1, with X, Y, Z, fp
	g2ProjPointBytes := fp.Bytes * 3
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
// func CopyToDevice(scalars []fr.Element, bytes int) (unsafe.Pointer, error) {
// 	devicePtr, cmErr := cudawrapper.CudaMalloc(bytes)
// 	if cmErr != nil {
// 		return nil, cmErr
// 	}
// 	ret := cudawrapper.CudaMemCpyHtoD[fr.Element](devicePtr, scalars, bytes)
// 	if ret != 0 {
// 		return nil, fmt.Errorf("CudaMemCpyHtoD fail with %d", ret)
// 	}
// 	err := MontConvOnDevice(devicePtr, len(scalars), false)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return devicePtr, nil
// }

func CopyToDevice(scalars []fr.Element, bytes int, copyDone chan unsafe.Pointer) {
	devicePtr, err := cudawrapper.CudaMalloc(bytes)
	if err != nil {
		fmt.Printf("err :%v \n", err)
	}
	ret := cudawrapper.CudaMemCpyHtoD[fr.Element](devicePtr, scalars, bytes)
	if ret != 0 {
		fmt.Printf("err ret :%d \n", ret)
	}
	err = MontConvOnDevice(devicePtr, len(scalars), false)
	if err != nil {
		fmt.Printf("err :%v \n", err)
	}

	copyDone <- devicePtr
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
	var b32 [96]byte
	copy(b32[:], fb[:96])

	v, e := fp.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to convert point %v got error %v", f, e))
	}

	return &v
}

func ToGnarkE2(f *icicle.G2Element) *fp.Element {
	fb := f.ToBytesLe()
	var b32 [96]byte
	copy(b32[:], fb[:96])

	v, e := fp.LittleEndian.Element(&b32)

	if e != nil {
		panic(fmt.Sprintf("unable to convert point %v got error %v", f, e))
	}

	return &v
}

func G2PointToGnarkJac(p *icicle.G2Point) *curve.G2Jac {
	x := ToGnarkE2(&p.X)
	y := ToGnarkE2(&p.Y)
	z := ToGnarkE2(&p.Z)
	var zSquared fp.Element
	zSquared.Mul(z, z)

	var X fp.Element
	X.Mul(x, z)

	var Y fp.Element
	Y.Mul(y, &zSquared)

	after := curve.G2Jac{
		X: X,
		Y: Y,
		Z: *z,
	}

	return &after
}
