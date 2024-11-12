package main

import (
	"encoding/json"
	"log"
	"math/big"
	"math/rand/v2"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const NB_ACCOUNTS = 1_000_000

func createWitnesses() (*witness.Witness, *witness.Witness, error) {
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

func main() {
	// Define the circuit
	circuit := SumAggregationCircuit{
		TotalSum: 0,
		Balances: make([]frontend.Variable, NB_ACCOUNTS),
	}
	t := time.Now()
	r1cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	} else {
		logDurationSince("Circuit compilation", t)
	}

	// Generate the Groth16 keys
	t = time.Now()
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to set up proving and verifying keys: %v", err)
	} else {
		logDurationSince("Groth16 setup and key generation", t)
	}

	// Crete witness
	t = time.Now()
	fullWitness, publicWitness, err := createWitnesses()
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	} else {
		log.Println("Witnesses creation", t)
	}

	// Generate proof
	t = time.Now()
	proof, err := groth16.Prove(r1cs, pk, *fullWitness)
	if err != nil {
		log.Fatalf("Failed to generate proof: %v", err)
	} else {
		logDurationSince("Proof generation", t)
		jsonProof, _ := json.Marshal(proof)
		log.Println("Proof generated successfully! ", string(jsonProof))
	}

	// Verify proof
	t = time.Now()
	err = groth16.Verify(proof, vk, *publicWitness)
	if err != nil {
		log.Fatalf("Failed to verify proof: %v", err)
	} else {
		logDurationSince("Proof verification", t)
	}

	log.Println("Proof verified successfully!")
}
