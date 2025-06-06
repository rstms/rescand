package main

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strings"
)

type Validator struct {
	passwd map[string][]byte
}

func EncodeApiKey(username, password string) string {
	credentials := fmt.Sprintf("%s:%s", username, password)
	apiKey := base64.StdEncoding.EncodeToString([]byte(credentials))
	return apiKey
}

func DecodeApiKey(apiKey string) (string, string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(apiKey)
	if err != nil {
		return "", "", fmt.Errorf("X-Api-Key decode failed: %v", err)
	}
	credentials := string(decodedBytes)
	username, password, ok := strings.Cut(credentials, ":")
	if !ok || (username == "") || (password == "") {
		return "", "", fmt.Errorf("invalid credentials format")
	}
	return username, password, nil
}

func NewValidator(filename string) (*Validator, error) {
	validator := Validator{
		passwd: make(map[string][]byte),
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) > 8 {
			if strings.HasPrefix(fields[8], "/home/") {
				validator.passwd[fields[0]] = []byte(fields[1])
			}
		}
	}
	return &validator, nil
}

func (v *Validator) validate(apiKey string) (string, error) {
	emailAddress, password, err := DecodeApiKey(apiKey)
	if err != nil {
		return "", err
	}
	username, _, _ := strings.Cut(emailAddress, "@")
	hash, ok := v.passwd[username]
	if !ok {
		return "", fmt.Errorf("unknown system username: %s", username)
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		return "", fmt.Errorf("system validation failure: %v", err)
	}
	return emailAddress, nil
}
