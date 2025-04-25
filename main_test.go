package main

import (
	"bytes"
	"encoding/json"
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
}

func InitializeTestMaildir(t *testing.T) {

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

func TestMaildirInit(t *testing.T) {
	InitializeTests(t)
	InitializeTestMaildir(t)
}

func parseRescanResponse(t *testing.T, body io.Reader, response interface{}) {
	decoder := json.NewDecoder(body)
	err := decoder.Decode(response)
	if err == nil {
		return
	}
	require.Equal(t, io.EOF, err)
}

func dumpStatus(t *testing.T, status *map[string]RescanStatus) {
	data, err := json.MarshalIndent(status, "", "  ")
	require.Nil(t, err)
	log.Println(string(data))
}

func TestRescanOne(t *testing.T) {
	InitializeTests(t)
	InitializeTestMaildir(t)
	viper.Set("rescan_dovecot_timeout_seconds", 0)
	viper.Set("rescan_prune_seconds", 5)
	messageId := viper.GetString("test.message_id")
	request := RescanRequest{
		Username:   viper.GetString("test.email"),
		Folder:     viper.GetString("test.path"),
		MessageIds: []string{messageId},
	}
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	req := httptest.NewRequest("POST", "/rescan/", bytes.NewBuffer(data))
	w := httptest.NewRecorder()
	handlePostRescan(w, req)
	result := w.Result()
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response RescanResponse
	parseRescanResponse(t, result.Body, &response)
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
	timeout := time.After(30 * time.Second)
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
	InitializeTests(t)
	InitializeTestMaildir(t)
	viper.Set("rescan_dovecot_timeout_seconds", 0)
	viper.Set("rescan_prune_seconds", 10)
	request := RescanRequest{
		Username:   viper.GetString("test.email"),
		Folder:     viper.GetString("test.path"),
		MessageIds: []string{},
	}
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	req := httptest.NewRequest("POST", "/rescan/", bytes.NewBuffer(data))
	w := httptest.NewRecorder()
	handlePostRescan(w, req)
	result := w.Result()
	require.Equal(t, result.StatusCode, http.StatusOK)
	var response RescanResponse
	parseRescanResponse(t, result.Body, &response)
	dumpStatus(t, &response.Status)
	require.Equal(t, 1, len(response.Status))
	var rescanId string
	for id, _ := range response.Status {
		rescanId = id
	}
	require.NotEmpty(t, rescanId)
	monitorRescan(t, rescanId)
}
