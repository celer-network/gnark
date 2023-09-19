package groth16

import (
	"fmt"
	"time"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cudawrapper "github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
	"github.com/ingonyama-zk/iciclegnark/curves/bn254"
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

func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) error {
	var convertErr error
	if is_into {
		_, convertErr = icicle.ToMontgomery(scalars_d, size)
	} else {
		_, convertErr = icicle.FromMontgomery(scalars_d, size)
	}
	return convertErr
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

func MsmOnDevice(scalars_d, points_d unsafe.Pointer, count, bucketFactor int, convert bool) (curve.G1Jac, unsafe.Pointer, error, time.Duration) {
	g1ProjPointBytes := fp.Bytes * 3
	out_d, err := cudawrapper.CudaMalloc(g1ProjPointBytes)
	if err != nil {
		return curve.G1Jac{}, nil, err, time.Since(time.Now())
	}

	msmTime := time.Now()
	ret := icicle.Commit(out_d, scalars_d, points_d, count, bucketFactor)
	timings := time.Since(msmTime)
	if ret == -1 {
		return curve.G1Jac{}, nil, fmt.Errorf("fail to do icicle.Commit in MsmOnDevice, return with -1"), time.Since(time.Now())
	}

	if convert {
		outHost := make([]icicle.G1ProjectivePoint, 1)
		ret = cudawrapper.CudaMemCpyDtoH[icicle.G1ProjectivePoint](outHost, out_d, g1ProjPointBytes)
		if ret == -1 {
			return curve.G1Jac{}, nil, fmt.Errorf("fail to do CudaMemCpyDtoH in MsmOnDevice, return with -1"), time.Since(time.Now())
		}
		retPoint := *bn254.G1ProjectivePointToGnarkJac(&outHost[0])
		ret = cudawrapper.CudaFree(out_d)
		if ret == -1 {
			return curve.G1Jac{}, nil, fmt.Errorf("fail to do CudaFree in MsmOnDevice, return with -1"), time.Since(time.Now())
		}
		return retPoint, nil, nil, timings
	}

	return curve.G1Jac{}, out_d, nil, timings
}

func MsmG2OnDevice(scalars_d, points_d unsafe.Pointer, count, bucketFactor int, convert bool) (curve.G2Jac, unsafe.Pointer, error, time.Duration) {
	g2ProjPointBytes := fp.Bytes * 6
	out_d, _ := cudawrapper.CudaMalloc(g2ProjPointBytes)

	msmTime := time.Now()
	icicle.CommitG2(out_d, scalars_d, points_d, count, bucketFactor)
	timings := time.Since(msmTime)

	if convert {
		outHost := make([]icicle.G2Point, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.G2Point](outHost, out_d, g2ProjPointBytes)
		retPoint := *bn254.G2PointToGnarkJac(&outHost[0])
		cudawrapper.CudaFree(out_d)
		return retPoint, nil, nil, timings
	}

	return curve.G2Jac{}, out_d, nil, timings
}

type CopyToDeviceRes struct {
	devicePtr unsafe.Pointer
	err       error
}

// TODO, if error, should release cuda mem?
func CopyToDevice(scalars []fr.Element, bytes int, copyDone chan CopyToDeviceRes) {
	defer close(copyDone)
	res := CopyToDeviceRes{}
	res.devicePtr, res.err = cudawrapper.CudaMalloc(bytes)
	if res.err != nil {
		copyDone <- res
		return
	}
	cpyRet := cudawrapper.CudaMemCpyHtoD[fr.Element](res.devicePtr, scalars, bytes)
	if cpyRet == -1 {
		res.err = fmt.Errorf("CopyToDevice cpy fail with -1")
		copyDone <- res
		return
	}
	res.err = MontConvOnDevice(res.devicePtr, len(scalars), false)
	if res.err != nil {
		copyDone <- res
		return
	}
}
