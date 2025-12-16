package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/rstms/go-daemon"
	"github.com/rstms/rspamd-classes/classes"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const serverName = "rescand"
const Version = "1.4.33"

const DEFAULT_CONFIG_FILE = "/etc/rescand/config.yaml"

const DEFAULT_LOG_FILE = "/var/log/rescand"
const DEFAULT_ADDRESS = "127.0.0.1"
const DEFAULT_PORT = 2017
const DEFAULT_SERVER_CERT = "/etc/rescand/rescand.pem"
const DEFAULT_SERVER_KEY = "/etc/rescand/rescand.key"
const DEFAULT_PASSWD_FILE = "/etc/master.passwd"

const SHUTDOWN_TIMEOUT = 5

var Verbose bool
var Debug bool
var serverState string
var serverBanner string

var validator *Validator
var filterctl *APIClient

var (
	signalFlag = pflag.String("signal", "", `send signal:
    stop - shutdown
    reload - reload config
    `)
	shutdown = make(chan struct{})
	reload   = make(chan struct{})
)

type Response struct {
	Success bool   `json:"Success"`
	User    string `json:"User"`
	Message string `json:"Message"`
	Request string `json:"Request"`
}

type ClassResponse struct {
	Response
	Class string `json:"Class"`
}

type ScanResponse struct {
	Response
	Books []string `json:"Books"`
}

type RescanResponse struct {
	Response
	Status map[string]RescanStatus
}

type StatusResponse struct {
	Response
	Banner string
	State  string
}

type UserDumpResponse struct {
	Response
	Password string              `json:"Password"`
	Classes  []classes.SpamClass `json:"Classes"`
	Books    map[string][]string `json:"Books"`
}

type UserBooksResponse struct {
	Response
	Books map[string][]string
}

type UserAccountsResponse struct {
	Response
	Accounts map[string]string
}

type AddBookRequest struct {
	Username    string
	Bookname    string
	Description string
}

type AddAddressRequest struct {
	Username string
	Bookname string
	Address  string
	Name     string
}

type ClassesResponse struct {
	Response
	Classes []classes.SpamClass
}

type ClassesRequest struct {
	Address string
	Classes []classes.SpamClass
}

type SieveTraceResponse struct {
	Response
	Enabled bool
}

type GmailAuthRequest struct {
	Username string
	Gmail    string
	JWT      string
}

func fail(w http.ResponseWriter, user, request, message string, status int) {
	log.Printf("  [%d] %s", status, message)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{User: user, Request: request, Success: false, Message: message})
}

func succeed(w http.ResponseWriter, message string, result interface{}) {
	status := http.StatusOK
	log.Printf("  [%d] %s", status, message)
	if Verbose {
		dump, err := json.MarshalIndent(result, "", "  ")
		if err != nil {

			log.Fatalln("failure marshalling response:", err)
		}
		log.Println(string(dump))
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}

func returnRescanStatus(w http.ResponseWriter, message string, rescanIds *[]string, response *RescanResponse) {
	response.User = "rescand"
	response.Message = message
	response.Success = true
	response.Status = make(map[string]RescanStatus)
	err := GetRescanStatus(rescanIds, &response.Status)
	if err != nil {
		fail(w, response.User, response.Request, "failed getting rescan status", http.StatusNotFound)
		return
	}
	succeed(w, response.Message, &response)
}

func handlePostRescan(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	_, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	var request RescanRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "rescan", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	requestString := fmt.Sprintf("start rescan: user=%s folder=%s messageIds=%v", request.Username, request.Folder, request.MessageIds)

	if Verbose {
		log.Println(requestString)
	}

	rescan, err := NewRescan(&request)
	if err != nil {
		fail(w, request.Username, requestString, fmt.Sprintf("Rescan fail: %v", err), http.StatusInternalServerError)
		return
	}

	var response RescanResponse
	rescanIds := []string{rescan.Status.Id}
	response.Request = requestId(r)
	returnRescanStatus(w, "rescan started", &rescanIds, &response)
}

func handleGetRescanStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	_, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	rescanIds := []string{r.PathValue("rescan_id")}
	requestString := fmt.Sprintf("get rescan status: %s", rescanIds[0])
	if Verbose {
		log.Println(requestString)
	}
	var response RescanResponse
	response.Request = requestId(r)
	returnRescanStatus(w, "rescan status", &rescanIds, &response)
}

func handleGetAllRescanStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	_, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	requestString := "get rescan status: all"
	if Verbose {
		log.Println(requestString)
	}
	var response RescanResponse
	response.Request = requestId(r)
	returnRescanStatus(w, "rescan status", nil, &response)
}

func handleDeleteRescan(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	_, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	rescanId := r.PathValue("rescan_id")
	requestString := fmt.Sprintf("delete rescan: %s", rescanId)
	if Verbose {
		log.Println(requestString)
	}
	var response Response
	response.User = "rescand"
	response.Success = false
	found, err := DeleteRescan(rescanId)
	if err != nil {
		response.Message = err.Error()
	} else if found {
		response.Success = true
		response.Message = "deleted"
	} else {
		response.Message = "not found"
	}
	response.Request = requestId(r)
	succeed(w, response.Message, &response)
}

func handleGetServerStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if Verbose {
		log.Printf("Status request\n")
	}

	response := StatusResponse{}
	response.Success = true
	response.User = "rescand"
	response.Message = "status: running"
	response.Banner = serverBanner
	response.State = serverState
	response.Request = requestId(r)

	if Verbose {
		log.Printf("response: %v\n", response)
	}

	succeed(w, response.Message, &response)
	return

}

func checkApiKey(w http.ResponseWriter, r *http.Request) (string, bool) {

	apiKey := r.Header["X-Api-Key"]
	if len(apiKey) != 1 || apiKey[0] == "" {
		fail(w, "system", "rescand", "API Key failure", 400)
		return "", false
	}
	username, err := validator.validate(apiKey[0])
	if err != nil {
		fail(w, "system", "rescand", fmt.Sprintf("%v", err), 400)
		return "", false
	}
	return username, true
}

func requestId(r *http.Request) string {
	id := r.Header["X-Request-Id"]
	if len(id) > 0 && id[0] != "" {
		return id[0]
	}
	return uuid.New().String()
}

func handleGetBooks(w http.ResponseWriter, r *http.Request) {
	sourceIp := r.Header["X-Real-Ip"]
	if len(sourceIp) != 1 || sourceIp[0] != "127.0.0.1" {
		fail(w, "system", "rescand", "unauthorized", http.StatusUnauthorized)
		return
	}
	apiKey := r.Header["X-Api-Key"]
	configKey := viper.GetString("localhost_api_key")
	if (len(apiKey) != 1) || (apiKey[0] != configKey) {
		log.Printf("header key: %s\n", apiKey[0])
		log.Printf("config key: %s\n", configKey)
		fail(w, "system", "rescand", "unauthorized", http.StatusUnauthorized)
		return
	}

	address := r.PathValue("address")
	requestString := fmt.Sprintf("books: %s", address)
	var dumpResponse UserDumpResponse
	_, err := filterctl.Get(fmt.Sprintf("/filterctl/dump/%s/", address), &dumpResponse)
	if err != nil {
		fail(w, address, requestString, fmt.Sprintf("%v", err), 500)
		return
	}
	var response UserBooksResponse
	response.Success = true
	response.User = address
	response.Request = requestString
	response.Message = fmt.Sprintf("book count: %d", len(dumpResponse.Books))
	response.Books = dumpResponse.Books
	succeed(w, response.Message, &response)
}

func handlePostGmailAuth(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	_, domain, ok := strings.Cut(viper.GetString("mailqueue_hostname"), ".")
	if !ok {
		log.Printf("domain config failed: %s\n", domain)
		fail(w, "system", "gmail_auth", "configuration failure", 500)
	}

	var origin string
	if len(r.Header["Origin"]) > 0 {
		origin = r.Header["Origin"][0]
	}
	log.Printf("origin: %s\n", origin)
	expectedOrigin := "https://webmail." + domain
	if origin != expectedOrigin {
		log.Printf("unauthorized origin: expected %s, got %s\n", expectedOrigin, origin)
		fail(w, "system", "gmail_auth", "unauthorized", http.StatusUnauthorized)
	}

	log.Printf("RemoteAddr: %s\n", r.RemoteAddr)
	sourceIp, _, ok := strings.Cut(r.RemoteAddr, ":")
	if !ok || sourceIp != "127.0.0.1" {
		fail(w, "system", "gmail_auth", "unauthorized", http.StatusUnauthorized)
	}

	var request GmailAuthRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "gmail_auth", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}

	if request.Username == "" {
		fail(w, "system", "gmail_auth", "missing username", http.StatusBadRequest)
		return
	}
	if request.Gmail == "" {
		fail(w, "system", "gmail_auth", "missing gmail address", http.StatusBadRequest)
	}
	localAddress := fmt.Sprintf("%s@%s", request.Username, domain)
	requestString := fmt.Sprintf("authorize %s as %s", localAddress, request.Gmail)

	log.Printf("localAddress: %s\n", localAddress)
	log.Printf("gmailAddress: %s\n", request.Gmail)
	log.Printf("JWT=%s\n", request.JWT)

	var dumpResponse UserDumpResponse
	_, err = filterctl.Get(fmt.Sprintf("/filterctl/dump/%s/", localAddress), &dumpResponse)
	if err != nil {
		fail(w, localAddress, requestString, "local account validation failed", 500)
		return
	}
	if dumpResponse.User != localAddress || len(dumpResponse.Password) == 0 {
		fail(w, localAddress, requestString, fmt.Sprintf("%s is not a valid address", localAddress), 404)
		return
	}

	//TODO: upload the JWT to the mailqueue to configure fetchmail

	var response Response
	response.Success = true
	response.Request = requestString
	response.Message = fmt.Sprintf("received gmail credential: %s == %s", localAddress, request.Gmail)
	succeed(w, response.Message, &response)
}

func handleGetUserDump(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	username, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	requestString := fmt.Sprintf("userdump: %s", username)
	if Verbose {
		log.Println(requestString)
	}
	var response UserDumpResponse
	_, err := filterctl.Get(fmt.Sprintf("/filterctl/dump/%s/", username), &response)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("%v", err), 500)
		return
	}

	var classesResponse ClassesResponse
	_, err = filterctl.Get(fmt.Sprintf("/filterctl/classes/%s/", username), &classesResponse)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("%v", err), 500)
		return
	}
	response.Classes = classesResponse.Classes
	response.Request = requestId(r)
	succeed(w, response.Message, &response)
}

func handleGetClasses(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	username, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	requestString := fmt.Sprintf("get user classes: %s", username)
	if Verbose {
		log.Println(requestString)
	}
	var response ClassesResponse
	_, err := filterctl.Get(fmt.Sprintf("/filterctl/classes/%s/", username), &response)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("%v", err), 500)
		return
	}
	response.Request = requestId(r)
	succeed(w, response.Message, &response)
}

func handlePostClasses(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	username, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	var request ClassesRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "rescand", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	request.Address = username
	requestString := fmt.Sprintf("set classes %s", request.Address)
	if Verbose {
		log.Printf("set classes: %+v\n", request)
	}

	var response ClassesResponse
	_, err = filterctl.Post(fmt.Sprintf("/filterctl/classes/%s/", username), &request, &response, nil)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("%v", err), 500)
		return
	}
	response.Request = requestId(r)
	succeed(w, response.Message, &response)
}

func handlePostBook(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	username, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	var request AddBookRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "rescand", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	request.Username = username
	requestString := fmt.Sprintf("add book %s %s", request.Username, request.Bookname)
	if Verbose {
		log.Printf("add book: %+v\n", request)
	}

	var response Response
	_, err = filterctl.Post("/filterctl/book/", &request, &response, nil)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("%v", err), 500)
		return
	}
	response.Request = requestId(r)
	succeed(w, response.Message, &response)
}

func handleDeleteBook(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	username, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	bookname := r.PathValue("book")
	requestString := fmt.Sprintf("delete book %s %s", username, bookname)
	if Verbose {
		log.Println(requestString)
	}
	var response Response
	_, err := filterctl.Delete(fmt.Sprintf("/filterctl/book/%s/%s/", username, bookname), &response)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("%v", err), 500)
		return
	}
	response.Request = requestId(r)
	succeed(w, response.Message, &response)
}

func handlePostAddress(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	username, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	var request AddAddressRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fail(w, "system", "rescand", fmt.Sprintf("failed decoding request: %v", err), http.StatusBadRequest)
		return
	}
	request.Username = username
	requestString := fmt.Sprintf("add address %s %s %s", request.Username, request.Bookname, request.Address)
	if Verbose {
		log.Printf("add address: %+v\n", request)
	}
	var response Response
	addBookAttempted := false
	for {
		_, err = filterctl.Post("/filterctl/address/", &request, &response, nil)
		if err != nil {
			fail(w, username, requestString, fmt.Sprintf("%v", err), 500)
			return
		}
		if response.Success || addBookAttempted {
			break
		}
		if strings.HasPrefix(response.Message, "api.AddAddress failed: 404 Not Found") {
			addBookAttempted = true
			log.Printf("address book not found; adding '%s'\n", request.Bookname)
			addBookRequest := AddBookRequest{Username: username, Bookname: request.Bookname, Description: request.Bookname}
			_, err = filterctl.Post("/filterctl/book/", &addBookRequest, &response, nil)
			if err != nil {
				fail(w, username, requestString, fmt.Sprintf("adding address book: %v", err), 500)
				return
			}
			if !response.Success {
				fail(w, username, requestString, fmt.Sprintf("failed adding address book: %s", response.Message), 500)
				return
			}
		} else {
			// add address was unsuccessful but the message does not indicate book not found
			break
		}
	}
	response.Request = requestId(r)
	succeed(w, response.Message, &response)
}

func handleDeleteAddress(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	username, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	bookname := r.PathValue("book")
	address := r.PathValue("address")
	requestString := fmt.Sprintf("delete address %s %s %s", username, bookname, address)
	if Verbose {
		log.Println(requestString)
	}
	var response Response
	_, err := filterctl.Delete(fmt.Sprintf("/filterctl/address/%s/%s/%s/", username, bookname, address), &response)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("%v", err), 400)
		return
	}
	response.Request = requestId(r)
	succeed(w, response.Message, &response)
}

func usernamePart(address string) string {
	username, _, _ := strings.Cut(address, "@")
	return username
}

func handleGetSieveTrace(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	address, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	username := usernamePart(address)
	requestString := fmt.Sprintf("get sieve_trace: %s", address)
	if Verbose {
		log.Println(requestString)
	}
	homeDir := filepath.Join("/home", username)
	if !IsDir(homeDir) {
		fail(w, username, requestString, fmt.Sprintf("unknown user: %s", username), 404)
		return
	}
	traceDir := filepath.Join(homeDir, "sieve_trace")
	var response SieveTraceResponse
	response.Success = true
	response.User = address
	if IsDir(traceDir) {
		response.Enabled = true
		response.Message = "sieve_trace enabled"
	} else {
		response.Enabled = false
		response.Message = "sieve_trace disabled"
	}
	response.Request = requestId(r)
	succeed(w, response.Message, &response)
}

func handlePutSieveTrace(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	address, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	username := usernamePart(address)
	requestString := fmt.Sprintf("enable sieve_trace: %s", address)
	if Verbose {
		log.Println(requestString)
	}
	homeDir := filepath.Join("/home", username)
	if !IsDir(homeDir) {
		fail(w, username, requestString, fmt.Sprintf("unknown user: %s", username), 404)
		return
	}
	traceDir := filepath.Join(homeDir, "sieve_trace")
	if !IsDir(traceDir) {
		err := os.Mkdir(traceDir, 0700)
		if err != nil {
			fail(w, username, requestString, fmt.Sprintf("%v", err), 500)
			return
		}
	}
	u, err := user.Lookup(username)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("unknown user: %s", username), 404)
		return
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("uid conversion failed: %v", err), 500)
		return
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("gid conversion failed: %v", err), 500)
		return
	}
	err = os.Chown(traceDir, uid, gid)
	if err != nil {
		fail(w, username, requestString, fmt.Sprintf("%v", err), 500)
		return
	}
	var response SieveTraceResponse
	response.User = address
	response.Success = true
	response.Request = requestId(r)
	response.Message = "sieve_trace enabled"
	response.Enabled = true
	succeed(w, response.Message, &response)
}

func handleDeleteSieveTrace(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	address, ok := checkApiKey(w, r)
	if !ok {
		return
	}
	username := usernamePart(address)
	requestString := fmt.Sprintf("disable sieve_trace: %s", address)
	if username != usernamePart(address) {
		fail(w, username, requestString, fmt.Sprintf("username mismatch: %s", username), 400)
		return
	}
	if Verbose {
		log.Println(requestString)
	}
	homeDir := filepath.Join("/home", username)
	if !IsDir(homeDir) {
		fail(w, username, requestString, fmt.Sprintf("unknown user: %s", username), 404)
		return
	}
	traceDir := filepath.Join(homeDir, "sieve_trace")
	if IsDir(traceDir) {
		err := os.RemoveAll(traceDir)
		if err != nil {
			fail(w, username, requestString, fmt.Sprintf("failed removing trace dir: %v", err), 500)
			return
		}
	}
	var response SieveTraceResponse
	response.User = address
	response.Success = true
	response.Request = requestId(r)
	response.Message = "sieve_trace disabled"
	response.Enabled = false
	succeed(w, response.Message, &response)
}

func IsDir(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	return stat.IsDir()
}

func runServer() {

	serverBanner = fmt.Sprintf("%s v%s uid=%d gid=%d started as PID %d", serverName, Version, os.Getuid(), os.Getgid(), os.Getpid())
	log.Println(serverBanner)

	if viper.GetBool("verbose") {
		log.Printf("config: %s\n", viper.ConfigFileUsed())
	}

	addr := viper.GetString("addr")
	port := viper.GetInt("port")
	listen := fmt.Sprintf("%s:%d", addr, port)
	serverCertFile := viper.GetString("server_cert")
	serverKeyFile := viper.GetString("server_key")
	caFile := viper.GetString("ca")
	validateClientCerts := false
	server := http.Server{
		Addr:        listen,
		IdleTimeout: 5 * time.Second,
	}

	if viper.GetBool("require_client_cert") && !viper.GetBool("insecure") {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("failed reading CA file '%s': %v", caFile, err)
		}
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			log.Fatalf("failed appending CA to cert pool: %v", err)
		}
		server.TLSConfig = &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caCertPool,
		}
		validateClientCerts = true
	}

	http.HandleFunc("POST /rescan/", handlePostRescan)
	http.HandleFunc("GET /rescan/{rescan_id}/", handleGetRescanStatus)
	http.HandleFunc("GET /rescan/", handleGetAllRescanStatus)
	http.HandleFunc("DELETE /rescan/{rescan_id}/", handleDeleteRescan)
	http.HandleFunc("GET /status/", handleGetServerStatus)
	http.HandleFunc("POST /book/", handlePostBook)
	http.HandleFunc("DELETE /book/{book}/", handleDeleteBook)
	http.HandleFunc("POST /address/", handlePostAddress)
	http.HandleFunc("DELETE /address/{book}/{address}/", handleDeleteAddress)
	http.HandleFunc("GET /userdump/", handleGetUserDump)
	http.HandleFunc("GET /classes/", handleGetClasses)
	http.HandleFunc("POST /classes/", handlePostClasses)
	http.HandleFunc("GET /sieve/trace/", handleGetSieveTrace)
	http.HandleFunc("PUT /sieve/trace/", handlePutSieveTrace)
	http.HandleFunc("DELETE /sieve/trace/", handleDeleteSieveTrace)
	http.HandleFunc("GET /books/{address}/", handleGetBooks)
	http.HandleFunc("POST /gmail/auth/", handlePostGmailAuth)

	go func() {
		mode := "daemon"
		if viper.GetBool("debug") {
			mode = "debug"
		}
		if viper.GetBool("insecure") {
			if !viper.GetBool("debug") {
				log.Fatalf("insecure flag only allowed in debug mode")
			}
			log.Printf("WARNING: running server with TLS disabled\n")
			serverState = fmt.Sprintf("listening on %s in %s mode", listen, mode)
			log.Println(serverState)
			err := server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				log.Fatalln("ListenAndServe failed: ", err)
			}
		} else {
			serverState = fmt.Sprintf("listening on %s in TLS %s mode", listen, mode)
			log.Println(serverState)
			if !validateClientCerts {
				log.Printf("WARNING: client certificate validation disabled\n")
			}
			err := server.ListenAndServeTLS(serverCertFile, serverKeyFile)
			if err != nil && err != http.ErrServerClosed {
				log.Fatalln("ListenAndServeTLS failed: ", err)
			}
		}
	}()
	initRelay()

	<-shutdown

	log.Println("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), SHUTDOWN_TIMEOUT*time.Second)
	defer cancel()

	err := server.Shutdown(ctx)
	if err != nil {
		log.Fatalln("Server Shutdown failed: ", err)
	}
	log.Println("shutdown complete")
}

func stopHandler(sig os.Signal) error {
	log.Println("received stop signal")
	shutdown <- struct{}{}
	return daemon.ErrStop
}

func reloadHandler(sig os.Signal) error {
	log.Println("received reload signal")
	return nil
}

func main() {

	var configFilename string
	var versionFlag bool
	var helpFlag bool

	pflag.String("addr", DEFAULT_ADDRESS, "listen address")
	pflag.Int("port", DEFAULT_PORT, "listen port")
	pflag.BoolP("debug", "d", false, "run in foreground mode logging to stdout")
	pflag.BoolVar(&helpFlag, "help", false, "show help")
	pflag.BoolP("verbose", "v", false, "verbose mode")
	pflag.BoolVar(&versionFlag, "version", false, "output program name and version")
	pflag.Bool("insecure", false, "disable certificate validation")
	pflag.String("logfile", DEFAULT_LOG_FILE, fmt.Sprintf("config file (default: %s)", DEFAULT_LOG_FILE))
	pflag.StringVarP(&configFilename, "config", "c", DEFAULT_CONFIG_FILE, fmt.Sprintf("config file (default: %s)", DEFAULT_CONFIG_FILE))
	pflag.Parse()

	if versionFlag {
		fmt.Printf("rescand version %s\n", Version)
		os.Exit(0)
	}

	if helpFlag {
		pflag.Usage()
		os.Exit(0)
	}

	initConfig(configFilename)
	for _, command := range pflag.Args() {
		switch command {
		case "version":
			fmt.Printf("%s v%s\n", os.Args[0], Version)
			os.Exit(0)
		case "config":
			showConfig()
			os.Exit(0)
		default:
			log.Fatalf("unknown command: '%s'\n", command)
		}
	}

	if viper.GetBool("debug") {
		go runServer()
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGTERM)
		<-sigs
		shutdown <- struct{}{}
	} else {
		daemonize()
	}
	os.Exit(0)
}

func initConfig(configFile string) {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading %s: %v", configFile, err)
	}
	viper.SetEnvPrefix("rescand")
	viper.AutomaticEnv()
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed reading my hostname: %v", err)
	}
	viper.SetDefault("hostname", hostname)
	viper.SetDefault("server_cert", DEFAULT_SERVER_CERT)
	viper.SetDefault("server_key", DEFAULT_SERVER_KEY)
	viper.SetDefault("passwd_file", DEFAULT_PASSWD_FILE)
	viper.SetDefault("require_client_cert", false)
	viper.BindPFlags(pflag.CommandLine)
	Verbose = viper.GetBool("verbose")
	Debug = viper.GetBool("debug")
}

func initRelay() {
	var err error
	filterctl, err = NewFilterctlClient()
	if err != nil {
		log.Fatalf("failed creating filterctl client: %v", err)
	}
	validator, err = NewValidator(viper.GetString("passwd_file"))
	if err != nil {
		log.Fatalf("failed creating validator: %v", err)
	}
}

func showConfig() {
	tempFile, err := os.CreateTemp(os.TempDir(), "rescan-*")
	if err != nil {
		log.Fatalf("failed creating temp file: %v", err)
	}
	defer tempFile.Close()
	defer os.Remove(tempFile.Name())
	err = viper.WriteConfigAs(tempFile.Name())
	if err != nil {
		log.Fatalf("failed writing config: %v", err)
	}
	fmt.Printf("# %s config: %s\n", serverName, viper.ConfigFileUsed())
	_, err = io.Copy(os.Stdout, tempFile)
	if err != nil {
		log.Fatalf("failed writing config: %v", err)
	}
}

func daemonize() {

	daemon.AddCommand(daemon.StringFlag(signalFlag, "stop"), syscall.SIGTERM, stopHandler)
	daemon.AddCommand(daemon.StringFlag(signalFlag, "reload"), syscall.SIGHUP, reloadHandler)

	ctx := &daemon.Context{
		LogFileName: viper.GetString("logfile"),
		LogFilePerm: 0600,
		WorkDir:     "/",
		Umask:       007,
	}

	if len(daemon.ActiveFlags()) > 0 {
		d, err := ctx.Search()
		if err != nil {
			log.Fatalln("Unable to signal daemon: ", err)
		}
		daemon.SendCommands(d)
		return
	}

	child, err := ctx.Reborn()
	if err != nil {
		log.Fatalln("Fork failed: ", err)
	}

	if child != nil {
		return
	}
	defer ctx.Release()

	go runServer()

	err = daemon.ServeSignals()
	if err != nil {
		log.Fatalln("Error: ServeSignals: ", err)
	}
}
