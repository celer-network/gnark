//go:build icicle

package icicle_bw6761

import (
	"github.com/consensys/gnark/backend"
	groth16_bw6761 "github.com/consensys/gnark/backend/groth16/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bw6-761"
	"sync"
)

const HasIcicle = true

var (
	setupDeviceLock sync.Mutex
	gpuResourceLock sync.Mutex
)

func SetupDevicePointers(pk *ProvingKey) error {
	// TODO, add lock here to make sure only init once
	return pk.setupDevicePointers()
}

func (pk *ProvingKey) setupDevicePointers() error {
	return nil
}

func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bw6761.Proof, error) {
	return nil, nil
}
