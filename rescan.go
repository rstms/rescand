package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/emersion/go-message/textproto"
	"github.com/spf13/viper"
	"io/fs"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RFC says 76; but we append a ] after breaking X-Spam-Score
const MAX_HEADER_LENGTH = 75

var IP_ADDR_PATTERN = regexp.MustCompile(`^[^[]*\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\].*`)

// these structures decode only what we need from the RSPAMD JSON response
type AddHeader struct {
	Order int
	Value string
}

type MilterMap struct {
	AddHeaders    map[string]AddHeader `json:"add_headers"`
	RemoveHeaders map[string]int       `json:"remove_headers"`
}

type Symbol struct {
	Description string
	MetricScore float32 `json:"metric_score"`
	Name        string
	Options     []string
	Score       float32
}

type RspamdResponse struct {
	Score      float32
	Required   float32 `json:"required_score"`
	Milter     MilterMap
	Urls       []string
	Thresholds map[string]float32
	Symbols    map[string]Symbol
}

type MessageFile struct {
	ID       string
	Pathname string
	Info     fs.FileInfo
	UID      uint32
	GID      uint32
}

func transformPath(user, folder string) string {
	var path string
	if folder == "/INBOX" {
		path = fmt.Sprintf("/home/%s/Maildir/cur", user)
	} else {
		mailDir := strings.ReplaceAll(folder, "/", ".")
		path = fmt.Sprintf("/home/%s/Maildir/%s/cur", user, mailDir)
	}
	if viper.GetBool("verbose") {
		log.Printf("transformPath: user=%s folder=%s path=%s\n", user, folder, path)
	}
	return path
}

func scanMessageFiles(dir string, messageIds []string) ([]MessageFile, error) {

	messageFiles := []MessageFile{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return messageFiles, fmt.Errorf("failed reading directory: %v", err)
	}
	if len(messageIds) == 0 {
		// no messsageId list, so just include all files
		for _, entry := range entries {
			if !entry.IsDir() {
				info, err := entry.Info()
				if err != nil {
					return messageFiles, fmt.Errorf("failed reading directory entry: %v", err)
				}
				messageFiles = append(messageFiles, MessageFile{
					Pathname: path.Join(dir, entry.Name()),
					Info:     info,
					UID:      info.Sys().(*syscall.Stat_t).Uid,
					GID:      info.Sys().(*syscall.Stat_t).Gid,
				})
			}
		}
	} else {
		// messageId list specified, search directory for matching messages
		total := len(messageIds)
		idMap := make(map[string]bool, total)
		for _, mid := range messageIds {
			idMap[mid] = true
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				pathname := path.Join(dir, entry.Name())
				mid, err := getMessageId(pathname)
				if err != nil {
					return messageFiles, err
				}
				if idMap[mid] {
					info, err := entry.Info()
					if err != nil {
						return messageFiles, fmt.Errorf("failed reading directory entry: %v", err)
					}
					messageFiles = append(messageFiles, MessageFile{
						ID:       mid,
						Pathname: pathname,
						Info:     info,
						UID:      info.Sys().(*syscall.Stat_t).Uid,
						GID:      info.Sys().(*syscall.Stat_t).Gid,
					})
				}
			}
			if len(messageFiles) == total {
				break
			}
		}
	}
	if viper.GetBool("verbose") {
		log.Printf("scanMessageFiles: dir=%s count=%d \n", dir, len(messageFiles))
		for i, messageFile := range messageFiles {
			log.Printf("  [%d] %+v\n", i, messageFile)
		}
	}
	return messageFiles, nil
}

func getMessageId(pathname string) (string, error) {
	file, err := os.Open(pathname)
	if err != nil {
		return "", fmt.Errorf("failed opening file: %v", err)
	}
	defer file.Close()
	header, err := textproto.ReadHeader(bufio.NewReader(file))
	if err != nil {
		return "", fmt.Errorf("ReadHeader failed: %v", err)
	}
	mid := header.Get("Message-Id")
	mid = strings.TrimSpace(mid)
	mid = strings.TrimLeft(mid, "<")
	mid = strings.TrimRight(mid, ">")
	mid = strings.TrimSpace(mid)
	if len(mid) == 0 {
		return "", fmt.Errorf("failed parsing Message-Id header")
	}
	if viper.GetBool("verbose") {
		log.Printf("getMessageId returning: %s\n", mid)
	}
	return mid, nil
}

func Rescan(userAddress, folder string, messageIds []string) (int, int, error) {
	var successCount int
	var failCount int

	if viper.GetBool("verbose") {
		log.Printf("Rescan: folder=%s\n", folder)
		for i, mid := range messageIds {
			log.Printf("   [%d] %s\n", i, mid)
		}
	}

	username, _, found := strings.Cut(userAddress, "@")
	if !found {
		return 0, 0, fmt.Errorf("failed parsing userAddress: %s", userAddress)
	}

	path := transformPath(username, folder)

	messageFiles, err := scanMessageFiles(path, messageIds)
	if err != nil {
		return 0, 0, fmt.Errorf("failed scanning message files")
	}

	client, err := NewAPIClient()
	if err != nil {
		return 0, 0, err
	}

	var wg sync.WaitGroup
	errorChan := make(chan error)
	successChan := make(chan string)

	for _, messageFile := range messageFiles {
		wg.Add(1)
		go func(client *APIClient, userAddress string, messageFile MessageFile) {
			defer wg.Done()
			err := RescanMessage(client, userAddress, messageFile)
			if err != nil {
				errorChan <- err
			}
			successChan <- messageFile.Pathname
		}(client, userAddress, messageFile)
	}

	go func() {
		wg.Wait()
		close(successChan)
		close(errorChan)
	}()

	openChannels := 2
	for openChannels > 0 {
		select {
		case err, ok := <-errorChan:
			if ok {
				failCount++
				fmt.Fprintf(os.Stderr, "Rescan failed: %v", err)
			} else {
				openChannels--
			}
		case msgFile, ok := <-successChan:
			if ok {
				successCount++
				log.Printf("Rescanned: %s\n", msgFile)
			} else {
				openChannels--
			}
		}
	}
	log.Printf("Rescan complete: success=%d, fail=%d\n", successCount, failCount)
	return successCount, failCount, nil
}

func RescanMessage(client *APIClient, userAddress string, messageFile MessageFile) error {

	content, err := os.ReadFile(messageFile.Pathname)
	lines := strings.Split(string(content), "\n")

	if viper.GetBool("verbose") {
		log.Println("---BEGIN SRC HEADERS---")
		for _, line := range lines {
			log.Println(line)
			if len(strings.TrimSpace(line)) == 0 {
				break
			}
		}
		log.Println("---END SRC HEADERS---")
	}

	headers, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(content)))
	keys := getKeys(&headers)
	if err != nil {
		return err
	}

	fromAddr, err := parseHeaderAddr(&headers, "From")
	if err != nil {
		return err
	}
	rcptToAddr, err := parseHeaderAddr(&headers, "To")
	if err != nil {
		return err
	}
	deliveredToAddr, err := parseHeaderAddr(&headers, "Delivered-To")
	if err != nil {
		return err
	}

	senderIP, err := getSenderIP(&headers)
	if err != nil {
		return err
	}

	var response RspamdResponse
	err = requestRescan(client, fromAddr, rcptToAddr, deliveredToAddr, senderIP, &content, &response)
	if err != nil {
		return err
	}

	err = mungeHeaders(client, &headers, userAddress, fromAddr, senderIP, &response, &keys)
	if err != nil {
		return err
	}

	if viper.GetBool("verbose") {
		log.Println("---BEGIN CHANGED HEADERS---")
		fields := headers.Fields()
		for fields.Next() {
			data, err := fields.Raw()
			if err != nil {
				fmt.Errorf("Raw failed: %v", err)
			}
			log.Printf("%s", string(data))
			/*
				log.Printf("--- BEGIN %s ---\n", fields.Key())
				log.Printf("\n%s", HexDump(data))
				log.Printf("%s: %s\n", fields.Key(), fields.Value())
				log.Println("*****")
				log.Printf("%s", string(data))
				log.Println("*****")
				log.Printf("--- END %s ---\n", fields.Key())
			*/
		}
		log.Println("---END CHANGED HEADERS---")
	}

	outputPath, err := generateOutputPath(&messageFile)
	if err != nil {
		return err
	}

	err = func() error {
		outfile, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed opening output file: %v", err)
		}
		defer outfile.Close()

		fields := headers.Fields()
		for fields.Next() {
			data, err := fields.Raw()
			if err != nil {
				fmt.Errorf("failed reading Raw header: %v", err)
			}
			_, err = fmt.Fprintf(outfile, "%s", string(data))
			if err != nil {
				fmt.Errorf("failed writing header line: %v", err)
			}
		}
		inHeaders := true
		for _, line := range lines {
			if inHeaders {
				if len(strings.TrimSpace(line)) == 0 {
					inHeaders = false
				} else {
					continue
				}
			}
			_, err := fmt.Fprintf(outfile, "%s\n", line)
			if err != nil {
				fmt.Errorf("failed writing body line: %v", err)
			}
		}
		return nil
	}()

	if err != nil {
		return err
	}

	err = replaceFile(messageFile, outputPath, outputPath+".bak")
	if err != nil {
		return err
	}
	return nil
}

func requestRescan(client *APIClient, fromAddr, rcptToAddr, deliveredToAddr, senderIP string, content *[]byte, response *RspamdResponse) error {

	requestHeaders := map[string]string{
		"settings":   `{"symbols_disabled": ["DATE_IN_PAST"]}`,
		"IP":         senderIP,
		"From":       fromAddr,
		"Rcpt":       rcptToAddr,
		"Deliver-To": deliveredToAddr,
		"Hostname":   viper.GetString("hostname"),
	}

	_, err := client.Post("/rspamc/checkv2", content, response, &requestHeaders)
	if err != nil {
		return err
	}

	if viper.GetBool("verbose") {

		//log.Printf("---BEGIN RESPONSE---\n%s\n---END RESPONSE---\n\n", text)
		//log.Printf("%+v\n", response)

		for name := range response.Milter.RemoveHeaders {
			log.Printf("remove: %s\n", name)
		}

		for name, _ := range response.Milter.AddHeaders {
			log.Printf("add: %s\n", name)
		}
	}
	return nil
}

func mungeHeaders(client *APIClient, headers *textproto.Header, userAddress, fromAddr, senderIP string, response *RspamdResponse, keys *[]string) error {

	// delete headers RSPAM wants to delete
	for key, _ := range response.Milter.RemoveHeaders {
		headers.Del(key)
	}

	// delete more headers
	for _, key := range *keys {
		if strings.HasPrefix(strings.ToLower(key), "x-spam") {
			headers.Del(key)
		}
		if strings.HasPrefix(strings.ToLower(key), "x-rspam") {
			headers.Del(key)
		}
	}

	skipAddKeys := map[string]bool{
		"X-Rspamd-Pre-Result": true,
		"X-Rspamd-Action":     true,
		"X-Spamd-Bar":         true,
		"X-Spamd-Result":      true,
		"X-Spam-Status":       true,
	}
	// copy the headers RSPAMD wants to add
	for key, value := range response.Milter.AddHeaders {
		if !skipAddKeys[key] {
			if viper.GetBool("verbose") {
				log.Printf("Adding: '%s': '%s'\n", key, value.Value)
			}
			if strings.ContainsRune(value.Value, '\n') {
				v := strings.ReplaceAll(value.Value, "\n", "\r\n")
				headers.Del(key)
				headers.AddRaw([]byte(key + ": " + v + "\r\n"))
			} else {
				headers.Set(strings.TrimSpace(key), strings.TrimSpace(value.Value))
			}
		}
	}

	symbols := []Symbol{}
	for _, symbol := range response.Symbols {
		symbols = append(symbols, symbol)
	}

	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].Name < symbols[j].Name
	})

	// generate new X-Spam-Status header
	spamStatus := fmt.Sprintf("%s required=%.3f\r\n", response.Milter.AddHeaders["X-Spam-Status"].Value, response.Required)
	delim := "\ttests["
	line := ""
	for _, symbol := range symbols {
		chunk := fmt.Sprintf("%s=%.3f", symbol.Name, symbol.Score)
		if len(line)+len(delim)+len(chunk) >= MAX_HEADER_LENGTH {
			spamStatus += line
			line = ""
			delim = "\r\n\t"
		}
		line += delim + chunk
		delim = ", "
	}
	if line != "" {
		spamStatus += delim + line
	}
	spamStatus += "]\r\n"
	headers.Del("X-Spam-Status")
	headers.AddRaw([]byte("X-Spam-Status: " + spamStatus))

	headers.Set("X-Spam-Score", fmt.Sprintf("%.3f / %.3f", response.Score, response.Required))

	senderScore, err := getSenderScore(senderIP)
	if err != nil {
		return err
	}
	headers.Set("X-SenderScore", fmt.Sprintf("%d", senderScore))

	books, err := client.ScanAddressBooks(userAddress, fromAddr)
	if err != nil {
		return err
	}
	for _, book := range books {
		headers.Add("X-Address-Book", book)
	}

	class, err := client.ScanSpamClass(userAddress, response.Score)
	if err != nil {
		return err
	}
	headers.Set("X-Spam-Class", class)

	var spamValue string
	if class == "spam" {
		spamValue = "yes"
	} else {
		spamValue = "no"
	}
	headers.Set("X-Spam", spamValue)

	*keys = []string{}
	fields := headers.Fields()
	for fields.Next() {
		*keys = append(*keys, fields.Key())
	}

	return nil
}

func getKeys(header *textproto.Header) []string {
	keys := []string{}
	fields := header.Fields()
	for fields.Next() {
		keys = append(keys, fields.Key())
	}
	return keys
}

func parseHeaderAddr(header *textproto.Header, key string) (string, error) {
	value := header.Get(key)
	if value == "" {
		return "", fmt.Errorf("header not found: %s", key)
	}
	emailAddress, err := parseEmailAddress(value)
	if err != nil {
		return "", fmt.Errorf("failed parsing email address from header: %v", err)
	}
	return emailAddress, nil
}

func getSenderIP(header *textproto.Header) (string, error) {
	received := header.Values("Received")
	if len(received) < 2 {
		return "", fmt.Errorf("insufficient Received headers")
	}
	match := IP_ADDR_PATTERN.FindStringSubmatch(received[1])
	if len(match) < 2 {
		return "", fmt.Errorf("Failed parsing IP address from: '%s'", received[1])
	}
	addr := match[1]
	if viper.GetBool("verbose") {
		log.Printf("getSenderIP returning: %s\n", addr)
	}
	return addr, nil
}

func getSenderScore(addr string) (int, error) {
	octets := strings.Split(addr, ".")
	lookup := fmt.Sprintf("%s.%s.%s.%s.score.senderscore.com", octets[3], octets[2], octets[1], octets[0])
	ips, err := net.LookupIP(lookup)
	if err != nil {
		return 0, fmt.Errorf("DNS query failed: %v", err)
	}
	var score int
	for _, ip := range ips {
		ip4 := ip.To4()
		score = int(ip4[3])
	}
	if viper.GetBool("verbose") {
		log.Printf("senderScore for %s is %d\n", addr, score)
	}
	return score, nil
}

// FIXME: this will copy the original to a backup and return the input path
// for now, write all modified files to a rescan subdir sibling to 'cur'
func generateOutputPath(messageFile *MessageFile) (string, error) {
	filePath := path.Dir(messageFile.Pathname)
	fileName := path.Base(messageFile.Pathname)
	parent := path.Dir(filePath)
	dir := path.Base(filePath)
	if dir != "cur" {
		return "", fmt.Errorf("dir not cur: path=%s filename=%s parent=%s dir=%s message=%+v\n", filePath, fileName, parent, dir, *messageFile)
	}
	outPath := path.Join(parent, "rescan", fileName)
	outDir := path.Dir(outPath)
	err := os.MkdirAll(outDir, 0700)
	if err != nil {
		return "", fmt.Errorf("failed creating output path: %v", err)
	}
	if viper.GetBool("verbose") {
		log.Printf("outPath=%s filePath=%s fileName=%s parent=%s dir=%s message=%+v\n", outPath, filePath, fileName, parent, dir, *messageFile)
	}
	return outPath, nil
}

// replace original with modified, preserving original as backup
func replaceFile(messageFile MessageFile, modified, backup string) error {
	err := os.Link(messageFile.Pathname, backup)
	if err != nil {
		return fmt.Errorf("failed linking '%s' -> '%s' : %v", messageFile.Pathname, backup, err)
	}
	err = os.Chtimes(modified, time.Now(), messageFile.Info.ModTime())
	if err != nil {
		return fmt.Errorf("failed changing modtime of '%s' : %v", modified, err)
	}
	err = os.Chmod(modified, messageFile.Info.Mode())
	if err != nil {
		return fmt.Errorf("failed changing mode bits of '%s' : %v", modified, err)
	}
	err = os.Chown(modified, int(messageFile.UID), int(messageFile.GID))
	if err != nil {
		return fmt.Errorf("failed changing ownership of '%s' : %v", modified, err)
	}
	err = os.Rename(modified, messageFile.Pathname)
	if err != nil {
		return fmt.Errorf("failed moving '%s' -> '%s' : %v", modified, messageFile.Pathname, err)
	}
	return nil
}
