package main

import (
	"bytes"
	"fmt"
	"os"
)

var magicBytes map[string][]byte = map[string][]byte{
	"gzip":  []byte{0x1f, 0x8b},
	"bzip2": []byte{0x42, 0x5a, 0x68},
	"zstd":  []byte{0x28, 0xb5, 0x2f, 0xfd},
}

func rewind(file *os.File) error {
	_, err := file.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("Seek failed: %v", err)
	}
	return nil
}

func DetectCompressedFile(file *os.File) (*string, error) {
	defer func() {
		err := rewind(file)
		if err != nil {
			panic(fmt.Sprintf("%v", err))
		}
	}()
	for name, magic := range magicBytes {
		moreMagic := make([]byte, len(magic))
		count, err := file.Read(moreMagic)
		if err != nil {
			return nil, fmt.Errorf("Read failed: %v", err)
		}
		if count != len(magic) {
			return nil, fmt.Errorf("unexpected read count: %d", count)
		}
		if bytes.Compare(magic, moreMagic) == 0 {
			return &name, nil
		}
		err = rewind(file)
		if err != nil {
			return nil, err
		}
	}
	return nil, nil
}
