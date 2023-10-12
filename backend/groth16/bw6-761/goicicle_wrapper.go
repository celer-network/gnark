package groth16

import (
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bw6761"
	"unsafe"
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
