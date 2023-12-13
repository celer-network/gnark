package groth16

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth162 "github.com/consensys/gnark/backend/groth16/bn254"
	groth163 "github.com/consensys/gnark/backend/groth16/bw6-761"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	plonk2 "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"log"
	"math/big"
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
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
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

	//_, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	_, innerVKPlonk, innerWitnessPlonk, innerProofPlonk := getInnerCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	// groth16
	/*circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)*/

	// plonk
	circuitVkPlonk, err := plonk2.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVKPlonk)
	assert.NoError(err)
	circuitWitnessPlonk, err := plonk2.ValueOfWitness[sw_bls12377.ScalarField](innerWitnessPlonk)
	assert.NoError(err)
	circuitProofPlonk, err := plonk2.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProofPlonk)
	assert.NoError(err)

	outerAssignment := &OuterCircuit6[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		//InnerWitness: [1]Witness[sw_bls12377.ScalarField]{circuitWitness},
		//Proof:        [1]Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{circuitProof},
		//VerifyingKey: circuitVk,

		InnerWitnessPlonk: circuitWitnessPlonk,
		ProofPlonk:        circuitProofPlonk,
		VerifyingKeyPlonk: circuitVkPlonk,

		N: 1,
		Q: 2,
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
	Proof        Proof[G1El, G2El]
	VerifyingKey VerifyingKey[G1El, G2El, GtEl]
	InnerWitness Witness[FR]
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
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	api.AssertIsEqual(c.N, 1)
	api.AssertIsEqual(c.Q, 2)
	return err
}

type OuterCircuit6[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	//Proof        [1]Proof[G1El, G2El]
	//VerifyingKey VerifyingKey[G1El, G2El, GtEl]
	//InnerWitness [1]Witness[FR]

	//
	ProofPlonk        plonk2.Proof[FR, G1El, G2El]
	VerifyingKeyPlonk plonk2.VerifyingKey[FR, G1El, G2El]
	InnerWitnessPlonk plonk2.Witness[FR]
	//

	N frontend.Variable `gnark:",public"`
	Q frontend.Variable `gnark:",public"`
}

func (c *OuterCircuit6[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	/*curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}

	verifier := NewVerifier(curve, pairing)
	for i, p := range c.Proof {
		err = verifier.AssertProof(c.VerifyingKey, p, c.InnerWitness[i])
		if err != nil {
			return err
		}
	}*/

	// plonk
	verifierPlonk, err := plonk2.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifierPlonk.AssertProof(c.VerifyingKeyPlonk, c.ProofPlonk, c.InnerWitnessPlonk)
	if err != nil {
		return err
	}

	api.AssertIsEqual(c.N, 1)
	api.AssertIsEqual(c.Q, 2)
	return err
}

func getInnerCommit(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, plonk.VerifyingKey, witness.Witness, plonk.Proof) {

	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitCommit{})
	assert.NoError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	assert.NoError(err)

	innerPK, innerVK, err := plonk.Setup(innerCcs, srs, srsLagrange)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitCommit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := plonk.Prove(innerCcs, innerPK, innerWitness, plonk2.GetNativeProverOptions(outer, field))

	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = plonk.Verify(innerProof, innerVK, innerPubWitness, plonk2.GetNativeVerifierOptions(outer, field))

	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type InnerCircuitCommit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitCommit) Define(api frontend.API) error {

	x := api.Mul(c.P, c.P)
	y := api.Mul(c.Q, c.Q)
	z := api.Add(x, y)

	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("builder does not implement frontend.Committer")
	}
	u, err := committer.Commit(x, z)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(u, c.N)
	return nil
}

type InnerCircuitNativeWoCommit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNativeWoCommit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

func getInnerWoCommit(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, plonk.VerifyingKey, witness.Witness, plonk.Proof) {
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitNativeWoCommit{})
	assert.NoError(err)
	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	assert.NoError(err)

	innerPK, innerVK, err := plonk.Setup(innerCcs, srs, srsLagrange)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitNativeWoCommit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := plonk.Prove(innerCcs, innerPK, innerWitness, plonk2.GetNativeProverOptions(outer, field))
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = plonk.Verify(innerProof, innerVK, innerPubWitness, plonk2.GetNativeVerifierOptions(outer, field))
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}
