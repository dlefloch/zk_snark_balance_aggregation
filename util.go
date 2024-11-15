package main

import (
	"encoding/hex"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/sha3"
)

func logDurationSince(action string, startTime time.Time) {
	// Example balances for three accounts
	duration := time.Since(startTime)
	log.Printf("%s took %.2f seconds\n", action, duration.Seconds())

}

// hashEthereumAddress hashes an Ethereum address using Keccak-256
func hashEthereumAddress(address string) string {
	// Remove the "0x" prefix if it exists
	address = strings.TrimPrefix(address, "0x")

	// Decode the Ethereum address from a hex string to bytes
	addressBytes, err := hex.DecodeString(address)
	if err != nil {
		log.Fatalf("Failed to decode address: %v", err)
	}

	// Generate a Keccak-256 hash of the address
	hash := sha3.NewLegacyKeccak256()
	hash.Write(addressBytes)
	return hex.EncodeToString(hash.Sum(nil))
}

func hashToBigInt(hashHex string) *big.Int {
	hashInt := new(big.Int)
	hashInt.SetString(hashHex, 16) // Convert hex string to *big.Int
	return hashInt
}

// Example: Convert frontend.Variable to *big.Int
func variableToBigInt(variable frontend.Variable) *big.Int {
	switch v := variable.(type) {
	case *big.Int:
		return v // Directly return if already *big.Int
	case int:
		return big.NewInt(int64(v)) // Handle integers
	case string:
		// Attempt parsing if variable is string
		result, _ := new(big.Int).SetString(v, 10)
		return result
	default:
		panic("Unsupported type for conversion")
	}
}
