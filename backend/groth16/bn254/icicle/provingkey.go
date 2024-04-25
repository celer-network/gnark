package icicle_bn254

import (
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/g2"
	"io"

	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"

	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
)

type deviceInfo struct {
	G1Device struct {
		A, B, K, Z core.HostSlice[bn254.Affine]
	}
	DomainDevice struct {
		Twiddles, TwiddlesInv core.DeviceSlice
	}
	G2Device struct {
		B core.HostSlice[g2.G2Affine]
	}
}

type ProvingKey struct {
	*groth16_bn254.ProvingKey
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

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bn254.VerifyingKey) error {
	return groth16_bn254.Setup(r1cs, pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bn254.DummySetup(r1cs, pk.ProvingKey)
}
