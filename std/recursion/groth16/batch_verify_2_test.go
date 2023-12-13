package groth16

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth162 "github.com/consensys/gnark/backend/groth16/bn254"
	groth163 "github.com/consensys/gnark/backend/groth16/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"log"
	"testing"
)

func TestFull(t *testing.T) {
	assert := test.NewAssert(t)
	_, innerVK, innerWitness, innerProof := getBLS12InBW6_5(assert)
	fmt.Printf("getBLS12InBW6 done \n")
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	outerAssignment := &OuterCircuit5[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: [2]Witness[sw_bw6761.ScalarField]{circuitWitness, circuitWitness},
		Proof:        [2]Proof[sw_bw6761.G1Affine, sw_bw6761.G2Affine]{circuitProof, circuitProof},
		VerifyingKey: circuitVk,
		N:            1,
		Q:            2,
	}

	field := ecc.BN254.ScalarField()
	err = test.IsSolved(outerAssignment, outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalln(err)
	}

	w, err := frontend.NewWitness(outerAssignment, field)
	assert.NoError(err)
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, outerAssignment)
	assert.NoError(err)
	fmt.Printf("254 constraints: %d \n", ccs.GetNbConstraints())
	pubWitness, err := w.Public()
	assert.NoError(err)

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalln(err)
	}

	proof, err := groth16.Prove(ccs, pk, w)
	assert.NoError(err)
	err = groth16.Verify(proof, vk, pubWitness)

	fmt.Printf("bn254 commitment: %d \n", len(proof.(*groth162.Proof).Commitments))

	assert.NoError(err)
	fmt.Println("bn254 done")
}

func getBLS12InBW6_5(assert *test.Assert) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	field := ecc.BW6_761.ScalarField()

	_, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerAssignment := &OuterCircuit2[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
		N:            1,
		Q:            2,
	}

	err = test.IsSolved(outerAssignment, outerAssignment, ecc.BW6_761.ScalarField())
	if err != nil {
		log.Fatalln(err)
	}

	aggWitness, err := frontend.NewWitness(outerAssignment, field)
	assert.NoError(err)
	aggCcs, err := frontend.Compile(field, r1cs.NewBuilder, outerAssignment)
	assert.NoError(err)
	fmt.Printf("bw761 constraints: %d \n", aggCcs.GetNbConstraints())
	aggPubWitness, err := aggWitness.Public()
	assert.NoError(err)

	pk, vk, err := groth16.Setup(aggCcs)
	if err != nil {
		log.Fatalln(err)
	}

	aggProof, err := groth16.Prove(aggCcs, pk, aggWitness)
	assert.NoError(err)
	err = groth16.Verify(aggProof, vk, aggPubWitness)
	assert.NoError(err)
	fmt.Printf("bw761 commitment: %d \n", len(aggProof.(*groth163.Proof).Commitments))
	return aggCcs, vk, aggPubWitness, aggProof
}

// for emulated outer circuit
type OuterCircuit5[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        [2]Proof[G1El, G2El]
	VerifyingKey VerifyingKey[G1El, G2El, GtEl]
	InnerWitness [2]Witness[FR]
	N            frontend.Variable `gnark:",public"`
	Q            frontend.Variable `gnark:",public"`
}

func (c *OuterCircuit5[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := NewVerifier(curve, pairing)
	err = verifier.AssertProof(c.VerifyingKey, c.Proof[0], c.InnerWitness[0])
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	err = verifier.AssertProof(c.VerifyingKey, c.Proof[1], c.InnerWitness[1])
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	api.AssertIsEqual(c.N, 1)
	api.AssertIsEqual(c.Q, 2)
	return err
}
