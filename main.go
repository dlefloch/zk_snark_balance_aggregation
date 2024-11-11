package main

import (
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func createWitnesses() (*witness.Witness, *witness.Witness, error) {
	// Example balances for three accounts
	balances := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}

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

func main() {
	// Define the circuit
	circuit := SumAggregationCircuit{
		TotalSum: 0,
		Balances: make([]frontend.Variable, 3),
	}
	r1cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}

	// Generate the Groth16 keys
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to set up proving and verifying keys: %v", err)
	}

	// Create witness for testing
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	}

	// Generate proof
	fullWitness, publicWitness, err := createWitnesses()
	proof, err := groth16.Prove(r1cs, pk, *fullWitness)
	if err != nil {
		log.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify proof
	err = groth16.Verify(proof, vk, *publicWitness)
	if err != nil {
		log.Fatalf("Failed to verify proof: %v", err)
	}

	log.Println("Proof verified successfully!")
}
