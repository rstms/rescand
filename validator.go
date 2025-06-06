package main

import (
	"encoding/base64"
	"fmt"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strings"
)

type Validator struct {
	filterctlPasswd map[string][]byte
	systemPasswd    map[string][]byte
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

func NewValidator(filterctl *APIClient, passwdFilename string) (*Validator, error) {
	validator := Validator{
		filterctlPasswd: make(map[string][]byte),
		systemPasswd:    make(map[string][]byte),
	}
	var response UserAccountsResponse
	_, err := filterctl.Get("/filterctl/accounts/", &response)
	if err != nil {
		return nil, err
	}
	for username, password := range response.Accounts {
		validator.add(username, password)
	}

	data, err := os.ReadFile(passwdFilename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) > 8 {
			if strings.HasPrefix(fields[8], "/home/") {
				validator.systemPasswd[fields[0]] = []byte(fields[1])
			}
		}
	}
	return &validator, nil
}

func (v *Validator) validate(apiKey string) (string, error) {
	if !viper.GetBool("validate_system_accounts") {
		return v.checkFilterctl(apiKey)
	}
	username, password, err := DecodeApiKey(apiKey)
	if err != nil {
		return "", err
	}
	username, _, _ = strings.Cut(username, "@")
	hash, ok := v.systemPasswd[username]
	if !ok {
		return "", fmt.Errorf("unknown username: %s", username)
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		return "", fmt.Errorf("validation failed: %v", err)
	}
	return username, nil
}

func (v *Validator) checkFilterctl(apiKey string) (string, error) {
	username, password, err := DecodeApiKey(apiKey)
	if err != nil {
		return "", err
	}
	hash, ok := v.filterctlPasswd[username]
	if !ok {
		return "", fmt.Errorf("unknown username: %s", username)
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		return "", fmt.Errorf("validation failure: %v\n", err)
	}
	return username, nil
}

func (v *Validator) add(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	v.filterctlPasswd[username] = hash
	return nil
}
