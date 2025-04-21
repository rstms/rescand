package main

import (
	"bytes"
	"encoding/json"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func InitializeTests(t *testing.T) {
	log.SetOutput(os.Stdout)
	viper.SetConfigFile("testdata/config.yaml")
	viper.ReadInConfig()
}

func TestRescanOne(t *testing.T) {
	InitializeTests(t)
	log.Printf("cert: %s\n", viper.GetString("cert"))
	request := RescanRequest{}
	request.Username = viper.GetString("test.username")
	request.Folder = "/INBOX"
	request.MessageIds = append(request.MessageIds, viper.GetString("test.message_id"))
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	req := httptest.NewRequest("POST", "/rescan/", bytes.NewBuffer(data))
	w := httptest.NewRecorder()
	handlePostRescan(w, req)
	result := w.Result()
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}

func TestRescanFolder(t *testing.T) {
	InitializeTests(t)
	request := RescanRequest{}
	request.Username = viper.GetString("test.username")
	request.Folder = "/INBOX"
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	req := httptest.NewRequest("POST", "/rescan/", bytes.NewBuffer(data))
	w := httptest.NewRecorder()
	handlePostRescan(w, req)
	result := w.Result()
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}
