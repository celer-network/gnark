package groth16

import (
	"fmt"
	"time"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	cudawrapper "github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bls12377"
	"github.com/ingonyama-zk/iciclegnark/curves/bls12377"
)

type OnDeviceData struct {
	p    unsafe.Pointer
	size int
}

func INttOnDevice(scalars_d, twiddles_d, cosetPowers_d unsafe.Pointer, size, sizeBytes int, isCoset bool) (unsafe.Pointer, []time.Duration) {
	var timings []time.Duration
	revTime := time.Now()
	icicle.ReverseScalars(scalars_d, size)
	revTimeElapsed := time.Since(revTime)
	timings = append(timings, revTimeElapsed)

	interpTime := time.Now()
	scalarsInterp := icicle.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)
	interpTimeElapsed := time.Since(interpTime)
	timings = append(timings, interpTimeElapsed)

	return scalarsInterp, timings
}

// func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) []time.Duration {
// 	var timings []time.Duration
// 	revTime := time.Now()
// 	if is_into {
// 		icicle.ToMontgomery(scalars_d, size)
// 	} else {
// 		icicle.FromMontgomery(scalars_d, size)
// 	}
// 	revTimeElapsed := time.Since(revTime)
// 	timings = append(timings, revTimeElapsed)

// 	return timings
// }

func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) (err error) {
	if is_into {
		_, err = icicle.ToMontgomery(scalars_d, size)
	} else {
		_, err = icicle.FromMontgomery(scalars_d, size)
	}
	return
}

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

func MsmOnDevice2(scalars_d, points_d unsafe.Pointer, count, bucketFactor int, convert bool) (curve.G1Jac, unsafe.Pointer, error, time.Duration) {
	g1ProjPointBytes := fp.Bytes * 3

	out_d, _ := cudawrapper.CudaMalloc(g1ProjPointBytes)

	msmTime := time.Now()
	icicle.Commit(out_d, scalars_d, points_d, count, bucketFactor)
	timings := time.Since(msmTime)

	if convert {
		outHost := make([]icicle.G1ProjectivePoint, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.G1ProjectivePoint](outHost, out_d, g1ProjPointBytes)
		retPoint := *bls12377.G1ProjectivePointToGnarkJac(&outHost[0])
		cudawrapper.CudaFree(out_d)
		return retPoint, nil, nil, timings
	}

	return curve.G1Jac{}, out_d, nil, timings
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
		retPoint := bls12377.G1ProjectivePointToGnarkJac(&outHost[0])
		return retPoint, nil, nil, timings
	}

	return nil, out_d, nil, timings
}

func MsmG2OnDevice2(scalars_d, points_d unsafe.Pointer, count, bucketFactor int, convert bool) (curve.G2Jac, unsafe.Pointer, error, time.Duration) {
	g2ProjPointBytes := fp.Bytes * 6 // X,Y,Z each with A0, A1 of fp.Bytes
	out_d, _ := cudawrapper.CudaMalloc(g2ProjPointBytes)

	msmTime := time.Now()
	icicle.CommitG2(out_d, scalars_d, points_d, count, bucketFactor)
	timings := time.Since(msmTime)

	if convert {
		outHost := make([]icicle.G2Point, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.G2Point](outHost, out_d, g2ProjPointBytes)
		retPoint := *bls12377.G2PointToGnarkJac(&outHost[0])
		cudawrapper.CudaFree(out_d)
		return retPoint, nil, nil, timings
	}

	return curve.G2Jac{}, out_d, nil, timings
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
		retPoint := bls12377.G2PointToGnarkJac(&outHost[0])
		return retPoint, nil, nil, timings
	}
	return nil, out_d, nil, timings
}

func CopyToDevice(scalars []fr.Element, bytes int, copyDone chan unsafe.Pointer) {
	devicePtr, _ := cudawrapper.CudaMalloc(bytes)
	cudawrapper.CudaMemCpyHtoD[fr.Element](devicePtr, scalars, bytes)
	MontConvOnDevice(devicePtr, len(scalars), false)

	copyDone <- devicePtr
}
