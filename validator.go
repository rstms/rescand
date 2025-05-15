package main

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
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

func NewValidator(filterctl *APIClient) (*Validator, error) {
	validator := Validator{
		passwd: make(map[string][]byte),
	}
	var response UserAccountsResponse
	_, err := filterctl.Get("/filterctl/accounts/", &response)
	if err != nil {
		return nil, err
	}
	for username, password := range response.Accounts {
		validator.add(username, password)
	}
	return &validator, nil
}

func (v *Validator) check(apiKey string) (string, error) {
	username, password, err := DecodeApiKey(apiKey)
	if err != nil {
		return "", err
	}
	hash, ok := v.passwd[username]
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
	v.passwd[username] = hash
	return nil
}
