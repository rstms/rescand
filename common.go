package main

import (
	"encoding/json"
	"log"
)

func FormatJSON(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("failed formatting JSON: %v", err)
	}
	return string(data)
}
