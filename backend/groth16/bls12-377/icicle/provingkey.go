package icicle_bls12377

import (
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	cs "github.com/consensys/gnark/constraint/bls12-377"
)

type ProvingKey struct {
	*groth16_bls12377.ProvingKey
	*deviceInfo
}

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bls12377.VerifyingKey) error {
	return groth16_bls12377.Setup(r1cs, pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bls12377.DummySetup(r1cs, pk.ProvingKey)
}
