package icicle_bn254

import (
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
)

type ProvingKey struct {
	*groth16_bn254.ProvingKey
	*deviceInfo
}

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bn254.VerifyingKey) error {
	return groth16_bn254.Setup(r1cs, pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bn254.DummySetup(r1cs, pk.ProvingKey)
}
