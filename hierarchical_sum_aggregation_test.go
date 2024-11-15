package main

import (
	"encoding/json"
	"fmt"
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

func createIndividualBalanceWitnesses() (*[]IndividualBalanceCircuit, *[]witness.Witness, *[]witness.Witness, error) {

	var err error

	circuits := make([]IndividualBalanceCircuit, NB_ACCOUNTS)
	fullWitnesses := make([]witness.Witness, NB_ACCOUNTS)
	publicWitnesses := make([]witness.Witness, NB_ACCOUNTS)
	for i := 0; i < NB_ACCOUNTS; i++ {
		// Generate random balances

		balance := big.NewInt(int64(rand.Int64()))
		blinding := big.NewInt(int64(1))
		accountHash := hashToBigInt(hashEthereumAddress(fmt.Sprintf("0x%064x", rand.Int64())))
		// Compute the commitment: commitment = balance * blinding + accountHash
		commitment := new(big.Int)
		commitment.Mul(balance, blinding)       // commitment = balance * blinding
		commitment.Add(commitment, accountHash) // commitment += accountHash

		circuits[i] = IndividualBalanceCircuit{
			Balance:     balance,
			Blinding:    blinding,
			AccountHash: accountHash,
			Commitment:  commitment,
		}

		fullWitnesses[i], err = frontend.NewWitness(&circuits[i], ecc.BLS12_381.ScalarField())
		if err != nil {
			return nil, nil, nil, err
		}

		publicWitnesses[i], err = frontend.NewWitness(&circuits[i], ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
		if err != nil {
			return nil, nil, nil, err
		}

	}

	return &circuits, &fullWitnesses, &publicWitnesses, nil
}

func createAggregatedBalanceWitnesses(individualCircuits *[]IndividualBalanceCircuit) (*witness.Witness, *witness.Witness, error) {

	var circuit *AggregatedBalanceCircuit
	var err error

	commitments := make([]frontend.Variable, NB_ACCOUNTS)
	totalCommitment := big.NewInt(0)
	for i := 0; i < NB_ACCOUNTS; i++ {
		commitments[i] = (*individualCircuits)[i].Commitment
		if commitments[i] == nil {
			return nil, nil, fmt.Errorf("Commitment for index %d is nil", i)
		}
		totalCommitment.Add(totalCommitment, variableToBigInt(commitments[i]))
	}

	circuit = &AggregatedBalanceCircuit{
		Commitments:     commitments,
		TotalCommitment: totalCommitment,
	}

	fullWitness, err := frontend.NewWitness(circuit, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, nil, err
	}

	publicWitness, err := frontend.NewWitness(circuit, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, nil, err
	}

	return &fullWitness, &publicWitness, nil
}

func TestIndividualBalanceProofsAndVerification(t *testing.T) {

	var err error
	var individualCircuit IndividualBalanceCircuit
	var individualCircuits *[]IndividualBalanceCircuit
	var aggregatedCircuit AggregatedBalanceCircuit
	var cs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var fullWitnesses *[]witness.Witness
	var publicWitnesses *[]witness.Witness
	var proofs []groth16.Proof
	var fullWitness *witness.Witness
	var publicWitness *witness.Witness
	var aggregatedProof groth16.Proof

	t.Run("CompileIndividualBalanceCircuitAndCompleteSetup", func(t *testing.T) {

		// Define the circuit
		individualCircuit = IndividualBalanceCircuit{}

		cs, err = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &individualCircuit)
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

	t.Run("CreateWitnessAndGenerateIndividualBalanceProof", func(t *testing.T) {

		if t.Failed() {
			t.Skip("Skipping because initialization failed")
		}

		// Crete witness
		individualCircuits, fullWitnesses, publicWitnesses, err = createIndividualBalanceWitnesses()
		if err != nil {
			t.Fatalf("Failed to create witness: %v", err)
		}
		t.Log("Witnesses created", t)

		// Generate proof
		proofs = make([]groth16.Proof, NB_ACCOUNTS)
		for i := 0; i < NB_ACCOUNTS; i++ {

			proofs[i], err = groth16.Prove(cs, pk, (*fullWitnesses)[i])
			if err != nil {
				t.Fatalf("Failed to generate proof: %v", err)
			}
			if DEBUG {
				jsonProof, _ := json.Marshal(proofs[i])
				t.Logf("Proof #%v generated successfully! %v", i, string(jsonProof))
			}

		}
		t.Logf("All proofs generated successfully!")
	})

	t.Run("VerifyIndividualBalanceProofs", func(t *testing.T) {

		if t.Failed() {
			t.Skip("Skipping because initialization or proof generation failed")
		}

		for i := 0; i < NB_ACCOUNTS; i++ {

			// Verify proof
			err = groth16.Verify(proofs[i], vk, (*publicWitnesses)[i])
			if err != nil {
				t.Fatalf("Failed to verify proof #%v: %v", i, err)
			}
			if DEBUG {
				t.Logf("Proof #%v verified successfully!", i)
			}

		}
		t.Logf("All proofs verified successfully!")

	})

	t.Run("CompileAggregatedBalanceCircuitAndCompleteSetup", func(t *testing.T) {

		// Define the circuit
		aggregatedCircuit = AggregatedBalanceCircuit{
			Commitments: make([]frontend.Variable, NB_ACCOUNTS),
		}

		cs, err = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &aggregatedCircuit)
		if err != nil {
			t.Fatalf("Failed to compile aggregated circuit: %v", err)
		}

		// Generate the Groth16 keys
		pk, vk, err = groth16.Setup(cs)
		if err != nil {
			t.Fatalf("Failed to set up proving and verifying keys: %v", err)
		}
		t.Log("Aggregated circuit compiled and keys generated successfully!")

	})

	t.Run("CreateWitnessAndGenerateAggregatedBalanceProof", func(t *testing.T) {

		if t.Failed() {
			t.Skip("Skipping because initialization failed")
		}

		// Crete witness
		fullWitness, publicWitness, err = createAggregatedBalanceWitnesses(individualCircuits)
		if err != nil {
			t.Fatalf("Failed to create aggregated witness: %v", err)
		}
		t.Log("Aggregated witnesses created", t)

		// Generate proof
		aggregatedProof, err = groth16.Prove(cs, pk, *fullWitness)
		if err != nil {
			t.Fatalf("Failed to generate aggregated proof: %v", err)
		}
		jsonProof, _ := json.Marshal(aggregatedProof)
		t.Logf("Aggregated proof generated successfully! %v", string(jsonProof))
	})

	t.Run("VerifyAggregatedBalanceProof", func(t *testing.T) {

		if t.Failed() {
			t.Skip("Skipping because initialization or aggregated proof generation failed")
		}

		// Verify proof
		err = groth16.Verify(aggregatedProof, vk, *publicWitness)
		if err != nil {
			t.Fatalf("Failed to verify aggregated proof: %v", err)
		}
		t.Logf("Aggregated proof verified successfully!")
	})

}
