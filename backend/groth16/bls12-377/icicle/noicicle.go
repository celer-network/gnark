//go:build !icicle

package icicle_bls12377

import (
	"fmt"

	"github.com/consensys/gnark/backend"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bls12-377"
)

const HasIcicle = false

type deviceInfo struct {
	DeviceReady bool
}

func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bls12377.Proof, error) {
	return nil, fmt.Errorf("icicle backend requested but program compiled without 'icicle' build tag")
}

func SetupDevicePointers(pk *ProvingKey) error {
	return fmt.Errorf("WARN: no icicle to use or load")
}
