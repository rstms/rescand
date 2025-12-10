package main

import (
	"encoding/base64"
	"fmt"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"slices"
	"strings"
)

type Validator struct {
	passwd   map[string][]byte
	verbose  bool
	insecure bool
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
	viper.SetDefault("validator_exclude_usernames", []string{"filterctl", "relay"})
	validator := Validator{
		passwd:   make(map[string][]byte),
		verbose:  viper.GetBool("validator_verbose"),
		insecure: viper.GetBool("validator_insecure"),
	}
	excludeUsers := viper.GetStringSlice("validator_exclude_usernames")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) > 8 {
			if !slices.Contains(excludeUsers, fields[0]) && strings.HasPrefix(fields[8], "/home/") {
				validator.passwd[fields[0]] = []byte(fields[1])
			}
		}
	}
	if validator.verbose && validator.insecure {
		log.Println("START_VALIDATE_INIT")
		for k, v := range validator.passwd {
			log.Printf("%s %s\n", k, v)
		}
		log.Println("END_VALIDATE_INIT")
	}
	return &validator, nil
}

func (v *Validator) validate(apiKey string, sourceIp string) (string, error) {
	log.Printf("validate: %s %s\n", apiKey, sourceIp)
	email, password, err := DecodeApiKey(apiKey)
	if err != nil {
		return "", err
	}
	username, _, _ := strings.Cut(email, "@")
	hash, ok := v.passwd[username]
	if v.verbose && v.insecure {
		log.Println("START_VALIDATE")
		log.Printf("apiKey=%s\n", apiKey)
		log.Printf("email=%s\n", email)
		log.Printf("password=%s\n", password)
		log.Printf("hash=%s\n", hash)
		log.Println("END_VALIDATE")
	}
	if !ok {
		err := fmt.Errorf("validate: unknown user '%s'", username)
		if v.verbose {
			log.Printf("%v\n", err)
		}
		return "", err
	}
	switch sourceIp {
	case "127.0.0.1":
		// if source is localhost, check password against api key from config file
		if password != viper.GetString("localhost_api_key") {
			err := fmt.Errorf("validate: user '%s': localhost_api_key mismatch", username)
			return "", err
		}
	default:
		err = bcrypt.CompareHashAndPassword(hash, []byte(password))
		if err != nil {
			err := fmt.Errorf("validate: user '%s': %v", username, err)
			return "", err
		}
	}
	if v.verbose {
		log.Printf("validated: '%s'\n", email)
	}
	return email, nil
}
