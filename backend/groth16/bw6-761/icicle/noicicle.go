//go:build !icicle

package icicle_bw6761

import (
	"fmt"

	"github.com/consensys/gnark/backend"
	groth16_bw6761 "github.com/consensys/gnark/backend/groth16/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bw6-761"
)

const HasIcicle = false

func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bw6761.Proof, error) {
	return nil, fmt.Errorf("icicle backend requested but program compiled without 'icicle' build tag")
}

func SetupDevicePointers(pk *ProvingKey) error {
	fmt.Println("WARN: no icicle to use or load")
	return nil
}
