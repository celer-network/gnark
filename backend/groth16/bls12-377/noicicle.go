//go:build !icicle

package groth16

import (
	"fmt"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bls12-377"
)

const HasIcicle = false

func ProveDevice(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*Proof, error) {
	return nil, fmt.Errorf("icicle backend requested but program compiled without 'icicle' build tag")
}

func SetupDevicePointers(pk *ProvingKey) error {
	fmt.Println("WARN: no icicle to use or load")
	return nil
}
