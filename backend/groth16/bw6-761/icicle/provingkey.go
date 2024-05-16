package icicle_bw6761

import (
	groth16_bw6761 "github.com/consensys/gnark/backend/groth16/bw6-761"
	cs "github.com/consensys/gnark/constraint/bw6-761"
)

type ProvingKey struct {
	*groth16_bw6761.ProvingKey
	*deviceInfo
}

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bw6761.VerifyingKey) error {
	return groth16_bw6761.Setup(r1cs, pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bw6761.DummySetup(r1cs, pk.ProvingKey)
}

func (p *ProvingKey) isDeviceReady() bool {
	return p.deviceInfo != nil && p.DeviceReady == true
}
