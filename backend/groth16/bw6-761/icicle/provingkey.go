package icicle_bw6761

import (
	groth16_bw6761 "github.com/consensys/gnark/backend/groth16/bw6-761"
	cs "github.com/consensys/gnark/constraint/bw6-761"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	"io"
)

type deviceInfo struct {
	G1Device struct {
		A, B, K, Z core.DeviceSlice
	}
	DomainDevice struct {
		Twiddles, TwiddlesInv     core.DeviceSlice
		CosetTable, CosetTableInv core.DeviceSlice
	}
	G2Device struct {
		B core.DeviceSlice
	}
	DenDevice             core.DeviceSlice
	InfinityPointIndicesK []int
}

type ProvingKey struct {
	*groth16_bw6761.ProvingKey
	*deviceInfo
}

// WriteTo writes binary encoding of the key elements to writer
// points are compressed
// use WriteRawTo(...) to encode the key without point compression
func (pk *ProvingKey) WriteTo(w io.Writer) (n int64, err error) {
	return pk.ProvingKey.WriteTo(w)
}

// UnsafeReadFrom behaves like ReadFrom excepts it doesn't check if the decoded points are on the curve
// or in the correct subgroup
func (pk *ProvingKey) UnsafeReadFrom(r io.Reader) (int64, error) {
	return pk.ProvingKey.UnsafeReadFrom(r)
}

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bw6761.VerifyingKey) error {
	return groth16_bw6761.Setup(r1cs, pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bw6761.DummySetup(r1cs, pk.ProvingKey)
}
