package main

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

type SumAggregationCircuit struct {
	TotalSum frontend.Variable   `gnark:"total_sum,public"` // Aggregated total (public output)
	Balances []frontend.Variable `gnark:"balances,secret"`  // User balances (private inputs)
}

func (circuit *SumAggregationCircuit) Define(api frontend.API) error {
	// Initialize aggregate sum as zero
	aggregateSum := frontend.Variable(0)

	// Loop through each user's balance to compute an aggregate sum
	for i := 0; i < len(circuit.Balances); i++ {
		// Add each balance to the aggregate sum
		aggregateSum = api.Add(aggregateSum, circuit.Balances[i])
	}

	// Ensure aggregateSum matches the declared TotalSum
	api.AssertIsEqual(aggregateSum, circuit.TotalSum)
	return nil
}

// Implement io.WriterTo
func (w *SumAggregationCircuit) WriteTo(writer io.Writer) (int64, error) {
	// Example implementation (serialize public and secret values to JSON)
	data, err := json.Marshal(w)
	if err != nil {
		return 0, err
	}
	n, err := writer.Write(data)
	return int64(n), err
}

// Implement io.ReaderFrom
func (w *SumAggregationCircuit) ReadFrom(reader io.Reader) (int64, error) {
	// Example implementation (deserialize JSON to populate the struct)
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(w)
	if err != nil {
		return 0, err
	}
	return int64(1 + len(w.Balances)), nil
}

// Implement encoding.BinaryMarshaler
func (w *SumAggregationCircuit) MarshalBinary() ([]byte, error) {
	return json.Marshal(w)
}

// Implement encoding.BinaryUnmarshaler
func (w *SumAggregationCircuit) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, w)
}

// Implement Public method
func (w *SumAggregationCircuit) Public() (witness.Witness, error) {
	return &SumAggregationCircuit{TotalSum: w.TotalSum}, nil
}

// Implement Vector method
func (w *SumAggregationCircuit) Vector() any {
	return append([]frontend.Variable{w.TotalSum}, w.Balances...)
}

// Implement ToJSON method
func (w *SumAggregationCircuit) ToJSON(s *schema.Schema) ([]byte, error) {
	return json.Marshal(w)
}

// Implement FromJSON method
func (w *SumAggregationCircuit) FromJSON(s *schema.Schema, data []byte) error {
	return json.Unmarshal(data, w)
}

// Implement Fill method
func (w *SumAggregationCircuit) Fill(nbPublic, nbSecret int, values <-chan any) error {
	w.Balances = make([]frontend.Variable, nbSecret)

	if nbPublic != 1 {
		return errors.New("expected 1 public input")
	}

	v, ok := <-values
	if !ok {
		return errors.New("not enough values for public inputs")
	}
	w.TotalSum = v.(int)

	for i := 0; i < nbSecret; i++ {
		v, ok := <-values
		if !ok {
			return errors.New("not enough values for secret inputs")
		}
		w.Balances[i] = v.(frontend.Variable)
	}

	return nil
}
