package main

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

type IndividualBalanceCircuit struct {
	Balance     frontend.Variable `gnark:"balance,secret"`
	Blinding    frontend.Variable `gnark:"blinding,secret"`
	AccountHash frontend.Variable `gnark:"account_hash,secret"`
	Commitment  frontend.Variable `gnark:"commitment,public"`
}

// PrecomputePedersenCommitment computes the Pedersen commitment
/*
func PrecomputePedersenCommitment(balance, blinding, accountHash *big.Int) (bls12381.G1Affine, error) {
	// Initialize generator points for G1
	g := bls12381.G1Affine{}
	g.Set(&bls12381.G1Gen)

	// Generate a random point h in G1
	var h bls12381.G1Affine
	_, err := h.SetRandom()
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	// Convert balance and blinding to field elements
	var balanceFr, blindingFr fr.Element
	balanceFr.SetBigInt(balance)
	blindingFr.SetBigInt(blinding)

	// Compute g^balance
	var balanceCommitment bls12381.G1Jac
	balanceCommitment.ScalarMultiplication(&g, balanceFr)

	// Compute h^blinding
	var blindingCommitment bls12381.G1Jac
	blindingCommitment.ScalarMultiplication(&h, blindingFr)

	// Hash the account identifier to the scalar field using MiMC
	mimcHash := mimc.NewMiMC()
	accountHashBytes := accountHash.Bytes()
	mimcHash.Write(accountHashBytes)
	accountHashFr := mimcHash.Sum(nil)

	var accountHashCommitment bls12381.G1Jac
	accountHashCommitment.ScalarMultiplication(&g, &accountHashFr)

	// Compute the final commitment: C = g^balance * h^blinding * H(accountHash)
	var commitment bls12381.G1Jac
	commitment.Set(&balanceCommitment).
		AddAssign(&blindingCommitment).
		AddAssign(&accountHashCommitment)

	// Convert to affine coordinates
	var commitmentAffine bls12381.G1Affine
	commitmentAffine.FromJacobian(&commitment)

	return commitmentAffine, nil
}
*/

func (circuit *IndividualBalanceCircuit) Define(api frontend.API) error {
	// Initialize MiMC hash function
	/*
		hash, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}

		// Compute g^balance
		g := sw_bls12381.G1AffineGenerator()
		balanceCommitment := sw_bls12381.ScalarMul(api, g, circuit.Balance)

		// Compute h^blinding
		h := sw_bls12381.G1AffineGenerator() // In practice, h should be a different point
		blindingCommitment := sw_bls12381.ScalarMul(api, h, circuit.Blinding)

		// Compute H(accountHash)
		accountHashCommitment := sw_bls12381.ScalarMul(api, g, accountHash)

		// Compute the final commitment: C = g^balance * h^blinding * H(accountHash)
		commitment := sw_bls12381.Add(api, balanceCommitment, blindingCommitment)
		commitment = sw_bls12381.Add(api, commitment, accountHashCommitment)
	*/

	// Placeholder commitment calculation in the circuit
	commitment := api.Add(api.Mul(circuit.Balance, circuit.Blinding), circuit.AccountHash)

	// Assert the computed commitment equals the public commitment
	api.AssertIsEqual(commitment, circuit.Commitment)
	return nil
}

// Implement io.WriterTo
func (w *IndividualBalanceCircuit) WriteTo(writer io.Writer) (int64, error) {
	// Example implementation (serialize public and secret values to JSON)
	data, err := json.Marshal(w)
	if err != nil {
		return 0, err
	}
	n, err := writer.Write(data)
	return int64(n), err
}

// Implement io.ReaderFrom
func (w *IndividualBalanceCircuit) ReadFrom(reader io.Reader) (int64, error) {
	// Example implementation (deserialize JSON to populate the struct)
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(w)
	if err != nil {
		return 0, err
	}
	return int64(4), nil
}

// Implement encoding.BinaryMarshaler
func (w *IndividualBalanceCircuit) MarshalBinary() ([]byte, error) {
	return json.Marshal(w)
}

// Implement encoding.BinaryUnmarshaler
func (w *IndividualBalanceCircuit) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, w)
}

// Implement Public method
func (w *IndividualBalanceCircuit) Public() (witness.Witness, error) {
	return &IndividualBalanceCircuit{Commitment: w.Commitment}, nil
}

// Implement Vector method
func (w *IndividualBalanceCircuit) Vector() any {
	return []frontend.Variable{w.Balance, w.Blinding, w.AccountHash, w.Commitment}
}

// Implement ToJSON method
func (w *IndividualBalanceCircuit) ToJSON(s *schema.Schema) ([]byte, error) {
	return json.Marshal(w)
}

// Implement FromJSON method
func (w *IndividualBalanceCircuit) FromJSON(s *schema.Schema, data []byte) error {
	return json.Unmarshal(data, w)
}

// Implement Fill method
func (w *IndividualBalanceCircuit) Fill(nbPublic, nbSecret int, values <-chan any) error {
	if nbSecret != 3 {
		return errors.New("expected 3 secret inputs")
	}
	if nbPublic != 1 {
		return errors.New("expected 1 public input")
	}

	v, ok := <-values
	if !ok {
		return errors.New("not enough values for secret input balance")
	}
	w.Balance = v.(frontend.Variable)

	v, ok = <-values
	if !ok {
		return errors.New("not enough values for secret input blinding")
	}
	w.Blinding = v.(frontend.Variable)

	v, ok = <-values
	if !ok {
		return errors.New("not enough values for secret input ")
	}
	w.AccountHash = v.(frontend.Variable)

	v, ok = <-values
	if !ok {
		return errors.New("not enough values for public input")
	}
	w.Commitment = v.(frontend.Variable)

	return nil
}

type AggregatedBalanceCircuit struct {
	Commitments     []frontend.Variable `gnark:"commitments,public"`
	TotalCommitment frontend.Variable   `gnark:"total_commitment,public"`
}

func (circuit *AggregatedBalanceCircuit) Define(api frontend.API) error {
	// Initialize sum of commitments
	aggregateSum := frontend.Variable(0)

	// Sum all individual commitments
	for _, commitment := range circuit.Commitments {
		aggregateSum = api.Add(aggregateSum, commitment)
	}

	// Ensure the sum of all commitments matches the declared total commitment
	api.AssertIsEqual(aggregateSum, circuit.TotalCommitment)
	return nil
}

// Implement io.WriterTo
func (w *AggregatedBalanceCircuit) WriteTo(writer io.Writer) (int64, error) {
	// Example implementation (serialize public and secret values to JSON)
	data, err := json.Marshal(w)
	if err != nil {
		return 0, err
	}
	n, err := writer.Write(data)
	return int64(n), err
}

// Implement io.ReaderFrom
func (w *AggregatedBalanceCircuit) ReadFrom(reader io.Reader) (int64, error) {
	// Example implementation (deserialize JSON to populate the struct)
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(w)
	if err != nil {
		return 0, err
	}
	return int64(len(w.Commitments) + 1), nil
}

// Implement encoding.BinaryMarshaler
func (w *AggregatedBalanceCircuit) MarshalBinary() ([]byte, error) {
	return json.Marshal(w)
}

// Implement encoding.BinaryUnmarshaler
func (w *AggregatedBalanceCircuit) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, w)
}

// Implement Public method
func (w *AggregatedBalanceCircuit) Public() (witness.Witness, error) {
	return &AggregatedBalanceCircuit{Commitments: w.Commitments, TotalCommitment: w.TotalCommitment}, nil
}

// Implement Vector method
func (w *AggregatedBalanceCircuit) Vector() any {
	return append(w.Commitments, []frontend.Variable{w.TotalCommitment}...)
}

// Implement ToJSON method
func (w *AggregatedBalanceCircuit) ToJSON(s *schema.Schema) ([]byte, error) {
	return json.Marshal(w)
}

// Implement FromJSON method
func (w *AggregatedBalanceCircuit) FromJSON(s *schema.Schema, data []byte) error {
	return json.Unmarshal(data, w)
}

// Implement Fill method
func (w *AggregatedBalanceCircuit) Fill(nbPublic, nbSecret int, values <-chan any) error {
	if nbSecret != 0 {
		return errors.New("secret input not expected")
	}

	for i := 0; i < nbSecret; i++ {
		v, ok := <-values
		if !ok {
			return errors.New("not enough values for public commitments")
		}
		w.Commitments[i] = v.(frontend.Variable)
	}

	v, ok := <-values
	if !ok {
		return errors.New("not enough values for public total commitment")
	}
	w.TotalCommitment = v.(frontend.Variable)

	return nil
}
