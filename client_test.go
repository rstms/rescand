package main

import (
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"log"
	"testing"
)

func TestScanBooks(t *testing.T) {
	InitializeTests(t)
	filterctl, err := NewAPIClient()
	require.Nil(t, err)
	username := viper.GetString("test.username")
	books, err := filterctl.ScanAddressBooks(username, username)
	require.Nil(t, err)
	require.IsType(t, []string{}, books)
	log.Printf("books: %v\n", books)
}

func TestScanSpamClass(t *testing.T) {
	InitializeTests(t)
	filterctl, err := NewAPIClient()
	require.Nil(t, err)
	username := viper.GetString("test.username")
	class, err := filterctl.ScanSpamClass(username, float32(900))
	require.Nil(t, err)
	require.Equal(t, "spam", class)
	log.Printf("class: %s\n", class)
}
