package bw6761test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type InnerCircuitNative struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNative) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

func getInner(assert *test.Assert, field *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuitNative{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitNative{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        regroth16.Proof[G1El, G2El]
	VerifyingKey regroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness regroth16.Witness[FR]
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := regroth16.NewVerifier(curve, pairing)
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func TestBw6761(t *testing.T) {
	assert := test.NewAssert(t)
	_, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	// outer proof
	circuitVk, err := regroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := regroth16.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := regroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}

	outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
	outerPubWitness, err := outerWitness.Public()
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, outerWitness, backend.WithIcicleAcceleration())
	assert.NoError(err)
	err = groth16.Verify(proof, vk, outerPubWitness)
	assert.NoError(err)
}
