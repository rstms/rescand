package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var ADDR_PATTERN = regexp.MustCompile(`^.*<([^>]*)>.*$`)
var EMAIL_PATTERN = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type APIClient struct {
	Client      *http.Client
	URL         string
	Headers     map[string]string
	verbose     bool
	moreVerbose bool
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

func NewFilterctlClient() (*APIClient, error) {
	filterctl_url := viper.GetString("filterctld_url")
	return NewAPIClient(filterctl_url, nil)
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
		URL:         url,
		Headers:     make(map[string]string),
		verbose:     viper.GetBool("verbose"),
		moreVerbose: viper.GetBool("more_verbose"),
	}

	if api.moreVerbose {
		api.verbose = true
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
			TLSClientConfig:   tlsConfig,
			IdleConnTimeout:   5 * time.Second,
			DisableKeepAlives: true,
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
	var requestBytes []byte
	var err error
	switch requestData.(type) {
	case nil:
	case *[]byte:
		requestBytes = *(requestData.(*[]byte))
	default:
		requestBytes, err = json.Marshal(requestData)
		if err != nil {
			return "", fmt.Errorf("failed marshalling JSON body for %s request: %v", method, err)
		}
	}

	request, err := http.NewRequest(method, a.URL+path, bytes.NewBuffer(requestBytes))
	if err != nil {
		return "", fmt.Errorf("failed creating %s request: %v", method, err)
	}

	// add the headers set up at instance init
	for key, value := range a.Headers {
		request.Header.Add(key, value)
	}

	if headers != nil {
		// add the headers passed in to this request
		for key, value := range *headers {
			request.Header.Add(key, value)
		}
	}

	if a.verbose {
		log.Printf("<-- %s %s (%d bytes)", method, a.URL+path, len(requestBytes))
		if a.moreVerbose {
			log.Println("BEGIN-REQUEST-HEADER")
			for key, value := range request.Header {
				log.Printf("%s: %s\n", key, value)
			}
			log.Println("END-REQUEST-HEADER")
			log.Println("BEGIN-REQUEST-BODY")
			log.Println(string(requestBytes))
			log.Println("END-REQUEST-BODY")
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
	if a.verbose {
		log.Printf("--> (%d bytes)\n", len(body))
	}
	err = json.Unmarshal(body, responseData)
	if err != nil {
		return "", fmt.Errorf("failed decoding JSON response: %v", err)
	}
	if err != nil {
		return "", err
	}
	var text []byte
	if a.verbose {
		text, err = json.MarshalIndent(responseData, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed formatting JSON response: %v", err)
		}
		if a.moreVerbose {
			log.Println("BEGIN-RESPONSE-BODY")
			log.Println(string(text))
			log.Println("END-RESPONSE-BODY")
		}
	}
	return string(text), nil
}

func (a *APIClient) ScanAddressBooks(username, address string) ([]string, error) {
	var response ScanResponse

	if a.verbose {
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

	if a.verbose {
		log.Printf("ScanAddressBooks returning: %v\n", response.Books)
	}
	return response.Books, nil
}

func (a *APIClient) ScanSpamClass(username string, score float32) (string, error) {

	if a.verbose {
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
	if a.verbose {
		log.Printf("ScanSpamClass returning: %s\n", response.Class)
	}
	return response.Class, nil
}

func parseEmailAddress(address string) (string, error) {
	parsed := address
	if strings.ContainsRune(address, '<') {
		matches := ADDR_PATTERN.FindStringSubmatch(address)
		if matches == nil || len(matches) < 2 {
			return "", fmt.Errorf("failed parsing address from: '%v'\n", address)
		}
		parsed = matches[1]
	}
	for _, addr := range strings.Split(parsed, " ") {
		if EMAIL_PATTERN.MatchString(addr) {
			return addr, nil
		}
	}
	return "", fmt.Errorf("failed validating email address: '%v'\n", parsed)
}
