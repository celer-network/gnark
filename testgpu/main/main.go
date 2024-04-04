package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/rs/zerolog"
	"log"
	"math/big"
	"os"
)

func main() {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	getInner(ecc.BN254.ScalarField())
	getInnerCommitment(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())
}

type InnerCircuit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

func getInner(field *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuit{})
	if err != nil {
		log.Fatalln(err)
	}
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		log.Fatalln(err)
	}

	// inner proof
	innerAssignment := &InnerCircuit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		log.Fatalln(err)
	}
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness, backend.WithIcicleAcceleration())
	if err != nil {
		log.Fatalln(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		log.Fatalln(err)
	}
	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	if err != nil {
		log.Fatalln(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type InnerCircuitCommitment struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitCommitment) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)

	commitment, err := api.Compiler().(frontend.Committer).Commit(c.P, c.Q, c.N)
	if err != nil {
		return err
	}

	api.AssertIsDifferent(commitment, 0)

	return nil
}

func getInnerCommitment(field, outer *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuitCommitment{})
	if err != nil {
		log.Fatalln(err)
	}
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		log.Fatalln(err)
	}

	// inner proof
	innerAssignment := &InnerCircuitCommitment{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		log.Fatalln(err)
	}
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness, regroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		log.Fatalln(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		log.Fatalln(err)
	}
	err = groth16.Verify(innerProof, innerVK, innerPubWitness, regroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		log.Fatalln(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof
}
