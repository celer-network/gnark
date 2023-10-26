package main

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/index-proof/core"
	"github.com/consensys/gnark/index-proof/utils"
	"github.com/ethereum/go-ethereum/rlp"
)

func main() {
	// generate CompiledConstraintSystem
	cur := ecc.BLS12_377
	ccs, err := frontend.Compile(cur.ScalarField(), r1cs.NewBuilder, &core.IndexCheckCircuit{})
	if err != nil {
		log.Fatal("frontend.Compile")
	}

	// groth16 zkSNARK: Setup
	var pk = groth16.NewProvingKey(cur)
	var vk = groth16.NewVerifyingKey(cur)

	log.Println("pk load done start.")
	pk, vk, err = groth16.Setup(ccs)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("pk load done.")

	var indexBuf []byte

	indexBuf = rlp.AppendUint64(indexBuf, uint64(1))
	input := utils.GetHexArray(fmt.Sprintf("%x", indexBuf), 6)
	if len(input) != 6 {
		log.Fatalf("invalid input, index: %d", 1)
	}
	var witnessInput [6]frontend.Variable
	for x, y := range input {
		witnessInput[x] = y
	}

	assignment := core.IndexCheckCircuit{
		Index:     1,
		RlpString: witnessInput,
	}

	witness, _ := frontend.NewWitness(&assignment, cur.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	for i := 0; i < 10; i++ {
		proof, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			debug.PrintStack()
			log.Fatal("prove computation failed...", err)
		}

		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			log.Fatal("groth16 verify failed...")
		}
	}
}

func WriteProvingKey(pk groth16.ProvingKey, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	_, err = pk.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func ReadProvingKey(filename string, pk groth16.ProvingKey) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = pk.UnsafeReadFrom(f)
	return err
}

func WriteVerifyingKey(vk groth16.VerifyingKey, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	_, err = vk.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func ReadVerifyingKey(filename string, vk groth16.VerifyingKey) error {
	f, _ := os.Open(filename)
	defer f.Close()
	_, err := vk.ReadFrom(f)
	if err != nil {
		return err
	}
	return nil
}
