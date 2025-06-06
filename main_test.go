package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rstms/rspamd-classes/classes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const allowMaildirDelete = "ALLOW_TESTS_TO_DELETE_HOME_MAILDIR"

func InitializeTests(t *testing.T) {
	log.SetOutput(os.Stdout)
	viper.SetConfigFile("testdata/config.yaml")
	viper.SetEnvPrefix("rescand")
	viper.AutomaticEnv()
	viper.ReadInConfig()
	Verbose = viper.GetBool("verbose")
	initRelay()
}

func InitializeTestMaildir(t *testing.T) {
	InitializeTests(t)

	// require environment var to continue
	allowed := os.Getenv(allowMaildirDelete)
	require.Equal(t, allowMaildirDelete, allowed, "WARNING: set env var to enable tests")

	maildir := viper.GetString("test.maildir")
	maildirPath := viper.GetString("test.maildir_path")
	path := viper.GetString("test.path")
	email := viper.GetString("test.email")
	file := viper.GetString("test.file")
	messageId := viper.GetString("test.message_id")

	log.Printf("maildir: %s\n", maildir)
	log.Printf("maildirPath: %s\n", maildirPath)
	log.Printf("path: %s\n", path)
	log.Printf("email: %s\n", email)
	log.Printf("file: %s\n", file)
	log.Printf("messageId: %s\n", messageId)

	err := os.RemoveAll(maildir)
	require.Nil(t, err)

	err = os.MkdirAll(filepath.Join(maildir, maildirPath, "cur"), 0700)
	require.Nil(t, err)

	err = os.MkdirAll(filepath.Join(maildir, maildirPath, "new"), 0700)
	require.Nil(t, err)

	err = os.MkdirAll(filepath.Join(maildir, maildirPath, "tmp"), 0700)
	require.Nil(t, err)

	err = os.MkdirAll(filepath.Join(maildir, maildirPath+".rescan"), 0700)
	require.Nil(t, err)

	err = os.MkdirAll(filepath.Join(maildir, maildirPath+".rescan", "cur"), 0700)
	require.Nil(t, err)

	err = os.MkdirAll(filepath.Join(maildir, maildirPath+".rescan", "new"), 0700)
	require.Nil(t, err)

	err = os.MkdirAll(filepath.Join(maildir, maildirPath+".rescan", "tmp"), 0700)
	require.Nil(t, err)

	err = filepath.Walk(filepath.Join("testdata", "cur"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		dst := filepath.Join(maildir, maildirPath, "cur", filepath.Base(path))
		log.Printf("\nsrc=%s\n", path)
		log.Printf("dst=%s\n", dst)
		err = copyFile(dst, path)
		return err
	})
	require.Nil(t, err)
}

func callHandler(path string, handler func(http.ResponseWriter, *http.Request), r *http.Request) *http.Response {
	username := viper.GetString("test_username")
	password := viper.GetString("test_password")
	apiKey := EncodeApiKey(username, password)
	r.Header["X-Api-Key"] = []string{apiKey}
	mux := http.NewServeMux()
	mux.HandleFunc(path, handler)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w.Result()
}

func TestMaildirInit(t *testing.T) {
	InitializeTestMaildir(t)
}

func parseResponse(t *testing.T, body io.Reader, response interface{}) {
	decoder := json.NewDecoder(body)
	err := decoder.Decode(response)
	if err == nil {
		return
	}
	require.Equal(t, io.EOF, err)
}

func dumpStatus(t *testing.T, statusMap *map[string]RescanStatus) {
	for id, status := range *statusMap {
		if status.Running {
			fmt.Printf("Status: %s Running [%d of %d]\n", id, status.Completed, status.Total)
		} else {
			data, err := json.MarshalIndent(status, "", "  ")
			require.Nil(t, err)
			fmt.Println(string(data))
		}
	}
}

func dumpResponse(t *testing.T, response interface{}) {
	data, err := json.MarshalIndent(response, "", "  ")
	require.Nil(t, err)
	fmt.Println(string(data))
}

func TestRescanOne(t *testing.T) {
	InitializeTestMaildir(t)
	messageId := viper.GetString("test.message_id")
	request := RescanRequest{
		Username:   viper.GetString("test.email"),
		Folder:     viper.GetString("test.path"),
		MessageIds: []string{messageId},
	}
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	req := httptest.NewRequest("POST", "/rescan/", bytes.NewBuffer(data))
	result := callHandler("POST /rescan/", handlePostRescan, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response RescanResponse
	parseResponse(t, result.Body, &response)
	dumpStatus(t, &response.Status)
	require.Equal(t, 1, len(response.Status))
	var rescanId string
	for id, _ := range response.Status {
		rescanId = id
	}
	require.NotEmpty(t, rescanId)
	monitorRescan(t, rescanId)
}

func monitorRescan(t *testing.T, rescanId string) {
	rescanIds := []string{rescanId}
	result := RescanResponse{Status: make(map[string]RescanStatus)}
	ticker := time.NewTicker(1 * time.Second)
	timeout := time.After(300 * time.Second)
	for {
		select {
		case <-timeout:
			require.True(t, false, "timeout awaiting rescan result")
		case <-ticker.C:
			err := GetRescanStatus(&rescanIds, &result.Status)
			require.Nil(t, err)
			dumpStatus(t, &result.Status)
			if !result.Status[rescanId].Running {
				return
			}
		}
	}
}

func TestRescanFolder(t *testing.T) {
	InitializeTestMaildir(t)
	viper.Set("rescan.prune_seconds", 120)
	request := RescanRequest{
		Username:   viper.GetString("test.email"),
		Folder:     viper.GetString("test.path"),
		MessageIds: []string{},
	}
	data, err := json.Marshal(&request)
	require.Nil(t, err)

	req := httptest.NewRequest("POST", "/rescan/", bytes.NewBuffer(data))
	result := callHandler("POST /rescan/", handlePostRescan, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response RescanResponse
	parseResponse(t, result.Body, &response)
	dumpStatus(t, &response.Status)
	require.Equal(t, 1, len(response.Status))
	var rescanId string
	for id, _ := range response.Status {
		rescanId = id
	}
	require.NotEmpty(t, rescanId)
	monitorRescan(t, rescanId)
}

func TestGetStatus(t *testing.T) {
	InitializeTests(t)
	req := httptest.NewRequest("GET", "/status/", nil)
	result := callHandler("GET /status/", handleGetServerStatus, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response StatusResponse
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)
}

func TestGetUserDump(t *testing.T) {
	InitializeTests(t)
	Verbose = true
	req := httptest.NewRequest("GET", "/userdump/", nil)
	result := callHandler("GET /userdump/", handleGetUserDump, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response UserDumpResponse
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)

}

func TestAddBook(t *testing.T) {
	InitializeTests(t)
	var request AddBookRequest
	request.Bookname = viper.GetString("test.bookname")
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	req := httptest.NewRequest("POST", "/book/", bytes.NewBuffer(data))
	result := callHandler("POST /book/", handlePostBook, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response Response
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)

}

func TestDeleteBook(t *testing.T) {
	InitializeTests(t)
	Verbose = true
	bookname := viper.GetString("test.bookname")
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/book/%s/", bookname), nil)
	result := callHandler("DELETE /book/{book}/", handleDeleteBook, req)
	require.Equal(t, http.StatusOK, result.StatusCode)
	var response Response
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)
}

func TestAddAddress(t *testing.T) {
	InitializeTests(t)
	var request AddAddressRequest
	request.Bookname = viper.GetString("test.bookname")
	request.Address = viper.GetString("test.address")
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	req := httptest.NewRequest("POST", "/address/", bytes.NewBuffer(data))
	result := callHandler("POST /address/", handlePostAddress, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response Response
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)

}

func TestDeleteAddress(t *testing.T) {
	InitializeTests(t)
	Verbose = true
	bookname := viper.GetString("test.bookname")
	address := viper.GetString("test.address")
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/address/%s/%s/", bookname, address), nil)
	result := callHandler("DELETE /address/{book}/{address}/", handleDeleteAddress, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response Response
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)
}

func TestGetClasses(t *testing.T) {
	InitializeTests(t)
	Verbose = true
	req := httptest.NewRequest("GET", "/classes/", nil)
	result := callHandler("GET /classes/", handleGetClasses, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response ClassesResponse
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)
}

func TestSetClasses(t *testing.T) {
	InitializeTests(t)
	Verbose = true
	request := ClassesRequest{
		Classes: []classes.SpamClass{
			classes.SpamClass{Name: "ham", Score: float32(0.0)},
			classes.SpamClass{Name: "possible", Score: float32(3.0)},
			classes.SpamClass{Name: "probable", Score: float32(10.0)},
			classes.SpamClass{Name: "spam", Score: float32(999.0)},
		},
	}
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	req := httptest.NewRequest("POST", "/classes/", bytes.NewBuffer(data))
	result := callHandler("POST /classes/", handlePostClasses, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response ClassesResponse
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)
}

func TestGetSieveTrace(t *testing.T) {
	InitializeTests(t)
	req := httptest.NewRequest("GET", "/sieve/trace/", nil)
	result := callHandler("GET /sieve/trace/", handleGetSieveTrace, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response Response
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)
}

func TestPutSieveTrace(t *testing.T) {
	InitializeTests(t)
	req := httptest.NewRequest("PUT", "/sieve/trace/", nil)
	result := callHandler("PUT /sieve/trace/", handlePutSieveTrace, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response Response
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)
}

func TestDeleteSieveTrace(t *testing.T) {
	InitializeTests(t)
	req := httptest.NewRequest("DELETE", "/sieve/trace/", nil)
	result := callHandler("DELETE /sieve/trace/", handleDeleteSieveTrace, req)
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response Response
	parseResponse(t, result.Body, &response)
	dumpResponse(t, &response)
}
