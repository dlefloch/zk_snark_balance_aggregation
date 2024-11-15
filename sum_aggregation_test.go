package main

import (
	"encoding/json"
	"math/big"
	"math/rand/v2"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func createSumAggregationWitnesses() (*witness.Witness, *witness.Witness, error) {
	// Example balances for three accounts
	balances := make([]*big.Int, NB_ACCOUNTS)
	for i := 0; i < NB_ACCOUNTS; i++ {
		// Generate random balances

		balances[i] = big.NewInt(int64(rand.Int64()))
	}
	// log.Println("Balances: ", balances)

	totalSum := big.NewInt(0)
	for _, balance := range balances {
		totalSum.Add(totalSum, balance)
	}

	// Set up circuit instance with values
	circuit := SumAggregationCircuit{
		TotalSum: totalSum,
		Balances: make([]frontend.Variable, len(balances)),
	}

	for i := 0; i < len(balances); i++ {
		circuit.Balances[i] = balances[i]
	}

	// Create a new witness instance
	fullWitness, err := frontend.NewWitness(&circuit, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, nil, err
	}

	publicWitness, err := frontend.NewWitness(&circuit, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, nil, err
	}

	return &fullWitness, &publicWitness, nil
}

func TestSumAggregationProofAndVerification(t *testing.T) {

	var err error
	var circuit SumAggregationCircuit
	var cs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var fw *witness.Witness
	var pw *witness.Witness
	var proof groth16.Proof

	t.Run("CompileCircuitAndCompleteSetup", func(t *testing.T) {

		// Define the circuit
		circuit = SumAggregationCircuit{
			TotalSum: 0,
			Balances: make([]frontend.Variable, NB_ACCOUNTS),
		}

		cs, err = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatalf("Failed to compile circuit: %v", err)
		}

		// Generate the Groth16 keys
		pk, vk, err = groth16.Setup(cs)
		if err != nil {
			t.Fatalf("Failed to set up proving and verifying keys: %v", err)
		}
		t.Log("Circuit compiled and keys generated successfully!")

	})

	t.Run("CreateWitnessAndGenerateProof", func(t *testing.T) {

		if t.Failed() {
			t.Skip("Skipping because initialization failed")
		}

		// Crete witness
		fw, pw, err = createSumAggregationWitnesses()
		if err != nil {
			t.Fatalf("Failed to create witness: %v", err)
		}
		t.Log("Witnesses created", t)

		// Generate proof
		proof, err = groth16.Prove(cs, pk, *fw)
		if err != nil {
			t.Fatalf("Failed to generate proof: %v", err)
		}
		jsonProof, _ := json.Marshal(proof)
		t.Log("Proof generated successfully! ", string(jsonProof))

	})

	t.Run("VerifyProof", func(t *testing.T) {

		if t.Failed() {
			t.Skip("Skipping because initialization or proof generation failed")
		}

		// Verify proof
		err = groth16.Verify(proof, vk, *pw)
		if err != nil {
			t.Fatalf("Failed to verify proof: %v", err)
		}
		t.Log("Proof verified successfully!")

	})
}
