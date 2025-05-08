package main

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestCompressedNone(t *testing.T) {
	file, err := os.Open("testdata/message.none")
	require.Nil(t, err)
	defer file.Close()
	compressed, err := DetectCompressedFile(file)
	require.Nil(t, err)
	require.Nil(t, compressed)
}

func TestCompressedGzip(t *testing.T) {
	file, err := os.Open("testdata/message.gzip")
	require.Nil(t, err)
	defer file.Close()
	compressed, err := DetectCompressedFile(file)
	require.Nil(t, err)
	require.Equal(t, *compressed, "gzip")
}

func TestCompressedBzip2(t *testing.T) {
	file, err := os.Open("testdata/message.bzip2")
	require.Nil(t, err)
	defer file.Close()
	compressed, err := DetectCompressedFile(file)
	require.Nil(t, err)
	require.Equal(t, *compressed, "bzip2")
}

func TestCompressedZstd(t *testing.T) {
	file, err := os.Open("testdata/message.zstd")
	require.Nil(t, err)
	defer file.Close()
	compressed, err := DetectCompressedFile(file)
	require.Nil(t, err)
	require.Equal(t, *compressed, "zstd")
}
