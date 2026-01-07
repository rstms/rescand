package main

import (
	"encoding/json"
	"log"
	"os"
)

func FormatJSON(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("failed formatting JSON: %v", err)
	}
	return string(data)
}

func IsFile(pathname string) bool {
	fileInfo, err := os.Stat(pathname)
	if err != nil {
		return false
	}
	return fileInfo.Mode().IsRegular()
}
