package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/rstms/go-daemon"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const serverName = "rescand"
const Version = "1.1.13"

const DEFAULT_CONFIG_FILE = "/etc/rescand/config.yaml"

const DEFAULT_LOG_FILE = "/var/log/rescand"
const DEFAULT_ADDRESS = "127.0.0.1"
const DEFAULT_PORT = 2017
const DEFAULT_SERVER_CERT = "/etc/rescand/rescand.pem"
const DEFAULT_SERVER_KEY = "/etc/rescand/rescand.key"

const SHUTDOWN_TIMEOUT = 5

var Verbose bool
var Debug bool
var serverState string
var serverBanner string

var (
	signalFlag = flag.String("s", "", `send signal:
    stop - shutdown
    reload - reload config
    `)
	shutdown = make(chan struct{})
	reload   = make(chan struct{})
)

type Response struct {
	Success bool   `json:"success"`
	User    string `json:"user"`
	Message string `json:"message"`
	Request string `json:"request"`
}

type ClassResponse struct {
	Response
	Class string
}

type ScanResponse struct {
	Response
	Books []string
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
	response.Request = requestString
	rescanIds := []string{rescan.Status.Id}
	returnRescanStatus(w, "rescan started", &rescanIds, &response)
}

func handleGetRescanStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	rescanIds := []string{r.PathValue("rescan_id")}
	requestString := fmt.Sprintf("get rescan status: %s", rescanIds[0])
	if Verbose {
		log.Println(requestString)
	}
	var response RescanResponse
	response.Request = requestString
	returnRescanStatus(w, "rescan status", &rescanIds, &response)
}

func handleGetAllRescanStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	requestString := "get rescan status: all"
	if Verbose {
		log.Println(requestString)
	}
	var response RescanResponse
	response.Request = requestString
	returnRescanStatus(w, "rescan status", nil, &response)
}

func handleDeleteRescan(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	rescanId := r.PathValue("rescan_id")
	requestString := fmt.Sprintf("delete rescan: %s", rescanId)
	if Verbose {
		log.Println(requestString)
	}
	var response Response
	response.User = "rescand"
	response.Request = requestString
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
	succeed(w, response.Message, &response)
}

func handleGetServerStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	requestString := "status request"

	if Verbose {
		log.Printf("Status request\n")
	}

	response := StatusResponse{}
	response.Success = true
	response.User = "rescand"
	response.Message = "status: running"
	response.Banner = serverBanner
	response.State = serverState
	response.Request = requestString

	if Verbose {
		log.Printf("response: %v\n", response)
	}

	succeed(w, response.Message, &response)
	return

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
	var server http.Server

	if viper.GetBool("insecure") {
		if !viper.GetBool("debug") {
			log.Fatalf("insecure flag only allowed in debug mode")
		}
		log.Printf("WARNING: client certificate validation disabled\n")
		server = http.Server{
			Addr:        listen,
			IdleTimeout: 5 * time.Second,
		}
	} else {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("failed reading CA file '%s': %v", caFile, err)
		}
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			log.Fatalf("failed appending CA to cert pool: %v", err)
		}
		tlsConfig := &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caCertPool,
		}
		server = http.Server{
			Addr:        listen,
			TLSConfig:   tlsConfig,
			IdleTimeout: 5 * time.Second,
		}
	}
	http.HandleFunc("POST /rescan/", handlePostRescan)
	http.HandleFunc("GET /rescan/{rescan_id}/", handleGetRescanStatus)
	http.HandleFunc("GET /rescan/", handleGetAllRescanStatus)
	http.HandleFunc("DELETE /rescan/{rescan_id}/", handleDeleteRescan)
	http.HandleFunc("GET /status/", handleGetServerStatus)

	go func() {
		mode := "daemon"
		if viper.GetBool("debug") {
			mode = "debug"
		}
		if viper.GetBool("insecure") {
			serverState = fmt.Sprintf("listening on %s in %s mode", listen, mode)
			log.Println(serverState)
			err := server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				log.Fatalln("ListenAndServe failed: ", err)
			}
		} else {
			serverState = fmt.Sprintf("listening on %s in TLS %s mode", listen, mode)
			log.Println(serverState)
			err := server.ListenAndServeTLS(serverCertFile, serverKeyFile)
			if err != nil && err != http.ErrServerClosed {
				log.Fatalln("ListenAndServeTLS failed: ", err)
			}
		}
	}()

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
	pflag.String("addr", DEFAULT_ADDRESS, "listen address")
	pflag.Int("port", DEFAULT_PORT, "listen port")
	pflag.BoolP("debug", "d", false, "run in foreground mode logging to stdout")
	pflag.BoolP("verbose", "v", false, "verbose mode")
	pflag.Bool("insecure", false, "disable certificate validation")
	pflag.String("logfile", DEFAULT_LOG_FILE, fmt.Sprintf("config file (default: %s)", DEFAULT_LOG_FILE))
	pflag.StringVarP(&configFilename, "config", "c", DEFAULT_CONFIG_FILE, fmt.Sprintf("config file (default: %s)", DEFAULT_CONFIG_FILE))
	pflag.Parse()
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
	viper.BindPFlags(pflag.CommandLine)
	Verbose = viper.GetBool("verbose")
	Debug = viper.GetBool("debug")
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
