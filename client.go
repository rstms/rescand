package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

var ADDR_PATTERN = regexp.MustCompile(`^.*<([^>]*)>.*$`)
var EMAIL_PATTERN = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type APIClient struct {
	Client  *http.Client
	URL     string
	Headers map[string]string
}

func GetViperPath(key string) (string, error) {
	path := viper.GetString(key)
	if len(path) < 2 {
		return "", fmt.Errorf("path %s too short: %s", key, path)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(path, "~") {
		path = filepath.Join(home, path[1:])
	}
	return path, nil

}

func NewAPIClient(url string, headers *map[string]string) (*APIClient, error) {

	certFile, err := GetViperPath("cert")
	if err != nil {
		return nil, err
	}
	keyFile, err := GetViperPath("key")
	if err != nil {
		return nil, err
	}
	caFile, err := GetViperPath("ca")
	if err != nil {
		return nil, err
	}

	api := APIClient{
		URL:     url,
		Headers: make(map[string]string),
	}

	if headers != nil {
		for key, value := range *headers {
			api.Headers[key] = value
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading client certificate pair: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate authority file: %v", err)
	}

	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("error opening system certificate pool: %v", err)
	}
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	api.Client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &api, nil
}

func (a *APIClient) Get(path string, response interface{}) (string, error) {
	return a.request("GET", path, nil, response, nil)
}

func (a *APIClient) Post(path string, request, response interface{}, headers *map[string]string) (string, error) {
	return a.request("POST", path, request, response, headers)
}

func (a *APIClient) Put(path string, response interface{}) (string, error) {
	return a.request("PUT", path, nil, response, nil)
}

func (a *APIClient) Delete(path string, response interface{}) (string, error) {
	return a.request("DELETE", path, nil, response, nil)
}

func (a *APIClient) request(method, path string, requestData, responseData interface{}, headers *map[string]string) (string, error) {
	if viper.GetBool("verbose") {
		log.Printf("<-- %s %s", method, a.URL+path)
	}
	var requestBuffer io.Reader
	switch requestData.(type) {
	case nil:
		break
	case *[]byte:
		if viper.GetBool("verbose") {
			log.Println("requestData: *[]byte")
		}
		requestBuffer = bytes.NewBuffer(*(requestData.(*[]byte)))
		break
	default:
		if viper.GetBool("verbose") {
			log.Println("requestData: JSON")
		}
		requestBytes, err := json.Marshal(requestData)
		if err != nil {
			return "", fmt.Errorf("failed marshalling JSON body for %s request: %v", method, err)
		}
		if viper.GetBool("verbose") {
			log.Printf("request: %s\n", string(requestBytes))
		}
		requestBuffer = bytes.NewBuffer(requestBytes)
		break
	}
	request, err := http.NewRequest(method, a.URL+path, requestBuffer)
	if err != nil {
		return "", fmt.Errorf("failed creating %s request: %v", method, err)
	}

	for key, value := range a.Headers {
		request.Header.Add(key, value)
	}

	if headers != nil {
		for key, value := range *headers {
			request.Header.Add(key, value)
			if viper.GetBool("verbose") {
				log.Printf("request header: %s: %s\n", key, value)
			}
		}
	}

	response, err := a.Client.Do(request)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failure reading response body: %v", err)
	}
	if response.StatusCode < 200 && response.StatusCode > 299 {
		return "", fmt.Errorf("API returned status [%d] %s", response.StatusCode, response.Status)
	}
	if viper.GetBool("verbose") {
		log.Printf("--> %v\n", string(body))
	}
	err = json.Unmarshal(body, responseData)
	if err != nil {
		return "", fmt.Errorf("failed decoding JSON response: %v", err)
	}
	if err != nil {
		return "", err
	}
	var text []byte
	if viper.GetBool("verbose") {
		text, err = json.MarshalIndent(responseData, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed formatting JSON response: %v", err)
		}
	}
	return string(text), nil
}

func (a *APIClient) ScanAddressBooks(username, address string) ([]string, error) {
	var response ScanResponse

	if viper.GetBool("debug") {
		log.Printf("ScanAddressBooks: %s %s\n", username, address)
	}

	username, err := parseEmailAddress(username)
	if err != nil {
		return []string{}, err
	}

	address, err = parseEmailAddress(address)
	if err != nil {
		return []string{}, err
	}

	_, err = a.Get(fmt.Sprintf("/filterctl/scan/%s/%s/", username, address), &response)
	if err != nil {
		return []string{}, err
	}

	if !response.Success {
		return []string{}, fmt.Errorf("filterctl books request failed: %v\n", response.Message)
	}

	if viper.GetBool("debug") {
		log.Printf("ScanAddressBooks returning: %v\n", response.Books)
	}
	return response.Books, nil
}

func (a *APIClient) ScanSpamClass(username string, score float32) (string, error) {

	if viper.GetBool("debug") {
		log.Printf("ScanSpamClass: %s %f\n", username, score)
	}

	username, err := parseEmailAddress(username)
	if err != nil {
		return "", err
	}

	var response ClassResponse

	_, err = a.Get(fmt.Sprintf("/filterctl/class/%s/%.4f/", username, score), &response)
	if err != nil {
		return "", err
	}
	if !response.Success {
		return "", fmt.Errorf("filterctl class request failed: %v\n", response.Message)
	}
	if viper.GetBool("debug") {
		log.Printf("ScanSpamClass returning: %s\n", response.Class)
	}
	return response.Class, nil
}

func parseEmailAddress(address string) (string, error) {
	if strings.ContainsRune(address, '<') {
		matches := ADDR_PATTERN.FindStringSubmatch(address)
		if matches == nil || len(matches) < 2 {
			return "", fmt.Errorf("failed parsing address from: '%v'\n", address)
		}
		address = matches[1]
	}

	if !EMAIL_PATTERN.MatchString(address) {
		return "", fmt.Errorf("invalid address: '%v'\n", address)
	}
	return address, nil
}
