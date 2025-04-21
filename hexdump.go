package main

import (
	"fmt"
	"strings"
)

func HexDump(data []byte) string {
	var output strings.Builder
	lineSize := 16
	for i := 0; i < len(data); i += lineSize {
		end := i + lineSize
		if end > len(data) {
			end = len(data)
		}
		line := data[i:end]

		output.WriteString(fmt.Sprintf("%08x  ", i))
		buf := make([]rune, lineSize)
		for j := 0; j < lineSize; j++ {
			var b byte
			if i+j < len(data) {
				output.WriteString(fmt.Sprintf("%02x ", line[j]))
				b = line[j]
			} else {
				output.WriteString("   ")
			}
			if b < 32 || b > 126 {
				buf[j] = '.'
			} else {
				buf[j] = rune(b)
			}
			if j == 7 {
				output.WriteString("- ")
			}

		}
		output.WriteString(fmt.Sprintf(" |%s|\n", string(buf)))
	}
	return output.String()
}
