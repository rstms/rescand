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
	"path/filepath"
	"testing"
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

func TestRescanOne(t *testing.T) {
	InitializeTests(t)
	InitializeTestMaildir(t)
	request := RescanRequest{}
	request.Username = viper.GetString("test.email")
	request.Folder = viper.GetString("test.path")
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
	InitializeTestMaildir(t)
	request := RescanRequest{}
	request.Username = viper.GetString("test.email")
	request.Folder = viper.GetString("test.path")
	data, err := json.Marshal(&request)
	require.Nil(t, err)
	req := httptest.NewRequest("POST", "/rescan/", bytes.NewBuffer(data))
	w := httptest.NewRecorder()
	handlePostRescan(w, req)
	result := w.Result()
	require.Equal(t, result.StatusCode, http.StatusOK)
	log.Printf("%+v", result)
}
