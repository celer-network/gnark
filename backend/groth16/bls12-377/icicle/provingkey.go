package icicle_bls12377

import (
	"io"
	"unsafe"

	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	cs "github.com/consensys/gnark/constraint/bls12-377"
)

type deviceInfo struct {
	G1Device struct {
		A, B, K, Z unsafe.Pointer
	}
	DomainDevice struct {
		Twiddles, TwiddlesInv     unsafe.Pointer
		CosetTable, CosetTableInv unsafe.Pointer
	}
	G2Device struct {
		B unsafe.Pointer
	}
	DenDevice             unsafe.Pointer
	InfinityPointIndicesK []int
}

type ProvingKey struct {
	*groth16_bls12377.ProvingKey
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

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bls12377.VerifyingKey) error {
	return groth16_bls12377.Setup(r1cs, pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bls12377.DummySetup(r1cs, pk.ProvingKey)
}