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
		retPoint := bn254.G1ProjectivePointToGnarkJac(&outHost[0])
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
		retPoint := bn254.G2PointToGnarkJac(&outHost[0])
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
