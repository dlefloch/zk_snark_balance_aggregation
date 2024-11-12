package main

import (
	"log"
	"time"
)

func logDurationSince(action string, startTime time.Time) {
	// Example balances for three accounts
	duration := time.Since(startTime)
	log.Printf("%s took %.2f seconds\n", action, duration.Seconds())

}
