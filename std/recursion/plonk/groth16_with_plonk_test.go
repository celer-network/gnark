package plonk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Data struct {
	Proof             string `json:"proof"`
	VerifyingKey      string `json:"vk"`
	InputCommitments  string `json:"input_commitments"`
	OutputCommitment  string `json:"output_commitment"`
	TogglesCommitment string `json:"toggles_commitment"`
}

func TestApp(t *testing.T) {
	assert := test.NewAssert(t)
	GetCustomAppInfos(assert)
}

func GetCustomAppInfos(assert *test.Assert) {

	jsonFile, err := os.Open("plonk_proof/two_plonk_proof.json")
	assert.NoError(err)
	byteValue, err := ioutil.ReadAll(jsonFile)
	assert.NoError(err)

	apps := make([]Data, 2)
	err = json.Unmarshal(byteValue, &apps)
	assert.NoError(err)

	for _, data := range apps {
		//data := apps[2]
		proofBytes, err := hexutil.Decode(data.Proof)
		assert.NoError(err)
		customProof := plonk.NewProof(ecc.BLS12_377)
		_, err = customProof.ReadFrom(bytes.NewReader(proofBytes))
		assert.NoError(err)

		customVKBytes, err := hexutil.Decode(data.VerifyingKey)
		assert.NoError(err)
		customVK := plonk.NewVerifyingKey(ecc.BLS12_377)
		_, err = customVK.ReadFrom(bytes.NewReader(customVKBytes))
		assert.NoError(err)

		plonkCircuitVk, err := ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](customVK)
		assert.NoError(err)
		plonkCircuitProof, err := ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](customProof)
		assert.NoError(err)
		plonkWitness := getWitness(assert, data)

		c := &AppCircuit{
			CustomProof:        plonkCircuitProof,
			CustomVerifyingKey: plonkCircuitVk,
			CustomInnerWitness: plonkWitness,
		}

		a := &AppCircuit{
			CustomProof:        plonkCircuitProof,
			CustomVerifyingKey: plonkCircuitVk,
			CustomInnerWitness: plonkWitness,
		}

		err = test.IsSolved(c, a, ecc.BW6_761.ScalarField())
		assert.NoError(err)

		ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, c)
		assert.NoError(err)
		fmt.Printf("ccs nb:%d \n", ccs.GetNbConstraints())
	}
}

func getWitness(assert *test.Assert, data Data) Witness[sw_bls12377.ScalarField] {
	var pub []emulated.Element[sw_bls12377.ScalarField]

	for _, inputCommitment := range strings.Split(data.InputCommitments, ",") {
		inputCommitmentBytes, err1 := hexutil.Decode(inputCommitment)
		assert.NoError(err1)
		pub = append(pub, emulated.ValueOf[sw_bls12377.ScalarField](inputCommitmentBytes))
	}

	togglesCommitmentBytes, err := hexutil.Decode(data.TogglesCommitment)
	assert.NoError(err)
	pub = append(pub, emulated.ValueOf[sw_bls12377.ScalarField](togglesCommitmentBytes))

	outputCommitmentBytes, err := hexutil.Decode(data.OutputCommitment)
	assert.NoError(err)

	pub = append(pub, emulated.ValueOf[sw_bls12377.ScalarField](outputCommitmentBytes[0:16]))
	pub = append(pub, emulated.ValueOf[sw_bls12377.ScalarField](outputCommitmentBytes[16:32]))

	return Witness[sw_bls12377.ScalarField]{Public: pub}
}

type AppCircuit struct {
	CustomProof        Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	CustomVerifyingKey VerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	CustomInnerWitness Witness[sw_bls12377.ScalarField]
}

func (c *AppCircuit) Define(api frontend.API) error {
	err := c.AssertAppProof(api)
	if err != nil {
		return err
	}
	return nil
}

func (c *AppCircuit) AssertAppProof(api frontend.API) error {
	plonkVerifier, err := NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return plonkVerifier.AssertProof(c.CustomVerifyingKey, c.CustomProof, c.CustomInnerWitness)
}
