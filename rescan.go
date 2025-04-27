package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/emersion/go-message/textproto"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var viperDefaultsSet bool

// RFC says 76; but we append a ] after breaking X-Spam-Score
const MAX_HEADER_LENGTH = 75
const TEMP_MAILDIR_ROOT = "/tmp/rescan"
const MAILDIR_ROOT = "/home"

var IP_ADDR_PATTERN = regexp.MustCompile(`^[^[]*\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\].*`)
var FILENAME_PATTERN = regexp.MustCompile(`^(.*),S=[0-9]+,W=[0-9]+:.*$`)

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
	MessageId string
	Pathname  string
	Info      fs.FileInfo
	UID       uint32
	GID       uint32
}

type RescanRequest struct {
	Username   string
	Folder     string
	MessageIds []string
}

func (r *RescanRequest) Copy() RescanRequest {
	dup := *r
	dup.MessageIds = make([]string, len(r.MessageIds))
	for i, id := range r.MessageIds {
		dup.MessageIds[i] = id
	}
	return dup
}

type RescanStatus struct {
	Id           string
	Running      bool
	Total        int
	Completed    int
	SuccessCount int
	FailCount    int
	LatestFile   string
	Request      RescanRequest
}

func (s *RescanStatus) Copy() RescanStatus {
	dup := *s
	dup.Request = s.Request.Copy()
	return dup
}

type RescanResult struct {
	index int
	err   error
}

type Rescan struct {
	Status       RescanStatus
	MessageFiles []MessageFile
	mutex        sync.Mutex
	filterctl    *APIClient
	doveadm      *DoveadmClient
	username     string
	mailBox      string
	mailDir      string
	wg           sync.WaitGroup
}

var jobs sync.Mutex
var RescanJobs map[string]*Rescan

func setViperDefaults() {
	viper.SetDefault("rescan_max_active", 8)
	viper.SetDefault("rescan_dovecot_timeout_seconds", 5)
	viper.SetDefault("rescan_dovecot_delay_ms", 100)
	viper.SetDefault("rescan_backup_enabled", false)
	viper.SetDefault("rescan_prune_seconds", 300)
	viper.SetDefault("rescan_sleep_seconds", 0)
	viperDefaultsSet = true
}

// copy rescan status into response map owned by caller
func GetRescanStatus(rescanIds *[]string, response *map[string]RescanStatus) error {
	jobs.Lock()
	defer jobs.Unlock()
	if rescanIds == nil {
		// return status of all rescan jobs
		for id, rescan := range RescanJobs {
			rescan.mutex.Lock()
			(*response)[id] = rescan.Status.Copy()
			rescan.mutex.Unlock()
		}
	} else {
		// return status of specified rescan jobs
		for _, id := range *rescanIds {
			rescan, ok := RescanJobs[id]
			if ok {
				rescan.mutex.Lock()
				(*response)[id] = rescan.Status.Copy()
				rescan.mutex.Unlock()
			} else {
				(*response)[id] = RescanStatus{}
			}
		}
	}
	return nil
}

func NewRescan(request *RescanRequest) (*Rescan, error) {

	if !viperDefaultsSet {
		setViperDefaults()
	}

	rescan := Rescan{
		Status: RescanStatus{
			Id:      uuid.New().String(),
			Running: true,
		},
		MessageFiles: make([]MessageFile, 0),
	}
	rescan.Status.Request = request.Copy()

	username, _, found := strings.Cut(request.Username, "@")
	if !found {
		return nil, fmt.Errorf("failed parsing emailAddress: %s", request.Username)
	}
	rescan.username = username

	err := rescan.setMaildir()
	if err != nil {
		return nil, err
	}

	err = rescan.scanMessageFiles()
	if err != nil {
		return nil, err
	}

	rescan.filterctl, err = NewFilterctlClient()
	if err != nil {
		return nil, err
	}

	rescan.doveadm, err = NewDoveadmClient()
	if err != nil {
		return nil, err
	}

	func() {
		jobs.Lock()
		defer jobs.Unlock()
		if RescanJobs == nil {
			if Verbose {
				log.Println("initializing RescanJobs")
			}
			RescanJobs = make(map[string]*Rescan)
		}
		RescanJobs[rescan.Status.Id] = &rescan
	}()

	rescan.wg.Add(1)
	rescan.Start()

	return &rescan, nil

}

func DeleteRescan(rescanId string) (bool, error) {
	jobs.Lock()
	defer jobs.Unlock()
	rescan, found := RescanJobs[rescanId]
	if found {
		if rescan.Status.Running {
			return false, fmt.Errorf("refusing delete of running rescan: %s", rescanId)
		}
		delete(RescanJobs, rescanId)
	}
	return found, nil
}

func (r *Rescan) Start() {

	maxActive := viper.GetInt("rescan_max_active")

	limitChan := make(chan struct{}, maxActive)
	startChan := make(chan int)
	resultChan := make(chan RescanResult)

	// local wg is the waitgroup for each message
	var wg sync.WaitGroup
	wg.Add(len(r.MessageFiles))

	// run rescan jobs in goprocesses and collect their results
	go func() {
		for openChannels := 2; openChannels > 0; {
			select {
			case index, ok := <-startChan:
				if ok {
					go func() {
						defer wg.Done()
						if Verbose {
							log.Printf("RescanMessage[%d] started\n", index)
						}
						var result RescanResult
						result.index = index
						result.err = r.RescanMessage(index)
						resultChan <- result
						<-limitChan
					}()
				} else {
					openChannels--
				}

			case result, ok := <-resultChan:
				if ok {
					func() {
						r.mutex.Lock()
						defer r.mutex.Unlock()
						r.Status.Completed++
						r.Status.LatestFile = r.MessageFiles[result.index].Pathname
						if result.err == nil {
							r.Status.SuccessCount++
							if Verbose {
								log.Printf("Rescan[%d] Succeeded: %s\n", result.index, r.Status.LatestFile)
							}
						} else {
							r.Status.FailCount++
							log.Printf("Rescan[%d] failed: %v\n", result.index, result.err)
						}
					}()
				} else {
					openChannels--
				}

			}
		}
	}()

	// start the jobs and wait for them to complete
	go func() {

		// r.wg is the waitgroup for the entire rescan job
		defer r.wg.Done()

		// start jobs through startChan - limitChan controls number of active jobs
		for i := 0; i < len(r.MessageFiles); i++ {
			limitChan <- struct{}{}
			startChan <- i
		}

		// all joobs have been started, wait for all of them to finish
		wg.Wait()

		// close channels since all jobs are complete
		close(startChan)
		close(resultChan)

		r.mutex.Lock()
		r.Status.Running = false
		r.doveadm = nil
		r.filterctl = nil
		r.mutex.Unlock()

		// setup a prune job to delete us out of RescanJobs after a while
		go func(rescanId string) {
			pruneSeconds := viper.GetInt64("rescan_prune_seconds")
			if pruneSeconds > 0 {
				<-time.After(time.Duration(pruneSeconds * int64(time.Second)))
				log.Printf("Pruning completed rescan: %s", rescanId)
				jobs.Lock()
				delete(RescanJobs, rescanId)
				jobs.Unlock()
			}
		}(r.Status.Id)

	}()
}

func (r *Rescan) IsRunning() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.Status.Running
}

func (r *Rescan) WaitStatus() RescanStatus {
	r.wg.Wait()
	return r.Status
}

func (r *Rescan) setMaildir() error {
	if r.Status.Request.Folder == "/INBOX" {
		r.mailDir = filepath.Join(MAILDIR_ROOT, r.username, "Maildir")
		r.mailBox = "INBOX"
	} else {
		mailDir := strings.ReplaceAll(r.Status.Request.Folder, "/", ".")
		if len(mailDir) < 2 {
			return fmt.Errorf("maildir too short: %s", mailDir)
		}
		r.mailBox = mailDir[1:]
		r.mailDir = filepath.Join(MAILDIR_ROOT, r.username, "Maildir", mailDir)
	}
	stat, err := os.Stat(r.mailDir)
	if err != nil {
		return fmt.Errorf("Maildir stat failed: %v", err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("Maildir is not a directory: %s", r.mailDir)
	}
	if Verbose {
		log.Printf("setMaildir: folder=%s mailbox=%s maildir=%s\n", r.Status.Request.Folder, r.mailBox, r.mailDir)
	}
	return nil
}

func (r *Rescan) scanMessageFiles() error {

	dir := filepath.Join(r.mailDir, "cur")

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed reading directory: %v", err)
	}
	if len(r.Status.Request.MessageIds) == 0 {
		// no messsageId list, so just include all files
		for _, entry := range entries {
			if !entry.IsDir() {
				info, err := entry.Info()
				if err != nil {
					return fmt.Errorf("failed reading directory entry: %v", err)
				}
				pathname := filepath.Join(dir, entry.Name())
				mid, err := getMessageId(pathname)
				if err != nil {
					return err
				}
				r.MessageFiles = append(r.MessageFiles, MessageFile{
					MessageId: mid,
					Pathname:  pathname,
					Info:      info,
					UID:       info.Sys().(*syscall.Stat_t).Uid,
					GID:       info.Sys().(*syscall.Stat_t).Gid,
				})
			}
		}
	} else {
		// messageId list specified, search directory for matching messages
		total := len(r.Status.Request.MessageIds)
		idMap := make(map[string]bool, total)
		for _, mid := range r.Status.Request.MessageIds {
			idMap[mid] = true
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				pathname := filepath.Join(dir, entry.Name())
				mid, err := getMessageId(pathname)
				if err != nil {
					return err
				}
				if idMap[mid] {
					info, err := entry.Info()
					if err != nil {
						return fmt.Errorf("failed reading directory entry: %v", err)
					}
					r.MessageFiles = append(r.MessageFiles, MessageFile{
						MessageId: mid,
						Pathname:  pathname,
						Info:      info,
						UID:       info.Sys().(*syscall.Stat_t).Uid,
						GID:       info.Sys().(*syscall.Stat_t).Gid,
					})
				}
			}
			if len(r.MessageFiles) == total {
				break
			}
		}
	}
	r.Status.Total = len(r.MessageFiles)
	if Verbose {
		log.Printf("scanMessageFiles: dir=%s count=%d \n", dir, len(r.MessageFiles))
		for i, messageFile := range r.MessageFiles {
			log.Printf("  [%d] %+v\n", i, messageFile)
		}
	}
	return nil
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
	if Verbose {
		log.Printf("getMessageId returning: %s\n", mid)
	}
	return mid, nil
}

func (r *Rescan) RescanMessage(index int) error {

	inputPathname := r.MessageFiles[index].Pathname
	if Verbose {
		log.Printf("RescanMessage: %d %s\n", index, inputPathname)
	}
	content, err := os.ReadFile(inputPathname)
	lines := strings.Split(string(content), "\n")

	if Debug {
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

	mid := headers.Get("Message-Id")
	mid = strings.TrimLeft(mid, "<")
	mid = strings.TrimRight(mid, ">")
	if mid != r.MessageFiles[index].MessageId {
		return fmt.Errorf("MessageId mismatch [%d] expected '%s' but got '%s'; %+v", index, r.MessageFiles[index].MessageId, mid, r.MessageFiles[index])
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
	err = r.requestRescan(fromAddr, rcptToAddr, deliveredToAddr, senderIP, &content, &response)
	if err != nil {
		return err
	}

	err = r.mungeHeaders(&headers, fromAddr, senderIP, &response, &keys)
	if err != nil {
		return err
	}

	if Debug {
		log.Println("---BEGIN CHANGED HEADERS---")
		fields := headers.Fields()
		for fields.Next() {
			data, err := fields.Raw()
			if err != nil {
				fmt.Errorf("Raw failed: %v", err)
			}
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
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

	outputPathname, err := r.generateOutputPathname("tmp", index)
	if err != nil {
		return err
	}

	err = func() error {
		outfile, err := os.Create(outputPathname)
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
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
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

	err = r.replaceFile(index, outputPathname)
	if err != nil {
		return err
	}
	return nil
}

func (r *Rescan) requestRescan(fromAddr, rcptToAddr, deliveredToAddr, senderIP string, content *[]byte, response *RspamdResponse) error {

	requestHeaders := map[string]string{
		"settings": `{"symbols_disabled": ["DATE_IN_PAST"]}`,
		"IP":       senderIP,
		"From":     fromAddr,
		"Rcpt":     rcptToAddr,
		"Hostname": viper.GetString("hostname"),
	}

	if deliveredToAddr != "" {
		requestHeaders["Deliver-To"] = deliveredToAddr
	}

	_, err := r.filterctl.Post("/rspamc/checkv2", content, response, &requestHeaders)
	if err != nil {
		return err
	}

	if Debug {

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

func (r *Rescan) mungeHeaders(headers *textproto.Header, fromAddr, senderIP string, response *RspamdResponse, keys *[]string) error {

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
			if Debug {
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
		log.Printf("WARNING: senderscore lookup failed: %v", err)
	} else {
		headers.Set("X-SenderScore", fmt.Sprintf("%d", senderScore))
	}

	books, err := r.filterctl.ScanAddressBooks(r.Status.Request.Username, fromAddr)
	if err != nil {
		return err
	}
	for _, book := range books {
		headers.Add("X-Address-Book", book)
	}

	class, err := r.filterctl.ScanSpamClass(r.Status.Request.Username, response.Score)
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
	if Debug {
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
	if Debug {
		log.Printf("senderScore for %s is %d\n", addr, score)
	}
	return score, nil
}

func (r *Rescan) generateOutputPathname(sub string, index int) (string, error) {

	outDir := filepath.Join(r.mailDir, sub)

	_, err := os.Stat(outDir)
	if err != nil {
		err := os.MkdirAll(outDir, 0700)
		if err != nil {
			return "", fmt.Errorf("failed creating output directory: %v", err)
		}
		err = r.chownPath(outDir)
		if err != nil {
			return "", err
		}
	}

	fileName := path.Base(r.MessageFiles[index].Pathname)
	var outputPath string
	if sub == "tmp/backup" {
		// we're generating the backup pathname, so ensure no clobber
		outputPath = generateNewBackupFilename(filepath.Join(outDir, fileName))
	} else {
		// we're generating the rescan output pathname, so strip the filename metadata
		match := FILENAME_PATTERN.FindStringSubmatch(fileName)
		if len(match) > 1 {
			fileName = match[1]
		}
		outputPath = filepath.Join(outDir, fileName)
	}
	return outputPath, nil
}

func (r *Rescan) chownPath(path string) error {

	userInfo, err := user.Lookup(r.username)
	if err != nil {
		return fmt.Errorf("failed user lookup: %v", err)
	}
	uid, err := strconv.Atoi(userInfo.Uid)
	if err != nil {
		return fmt.Errorf("failed uid conversion: %v", err)
	}
	gid, err := strconv.Atoi(userInfo.Gid)
	if err != nil {
		return fmt.Errorf("failed gid conversion: %v", err)
	}
	err = os.Chown(path, uid, gid)
	if err != nil {
		return fmt.Errorf("failed maildir chown: %v", err)
	}
	return nil
}

// copy file to dst from src dst preserving mode, ownership, and modification time
func copyFile(dst, src string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("copyFile: src Stat failed: %v", err)
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("copyFile: src Open failed: %v", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("copyFile: dst Create failed: %v", err)
	}
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("copyFile: Copy failed: %v", err)
	}
	dstFile.Close()

	// replicate access mode bits
	err = os.Chmod(dst, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("copyFile: Chmod failed: %v", err)
	}

	// replicate modification time
	err = os.Chtimes(dst, time.Now(), srcInfo.ModTime())
	if err != nil {
		return fmt.Errorf("copyFile: Chtimes failed: %v", err)
	}

	// replicate ownership
	uid := srcInfo.Sys().(*syscall.Stat_t).Uid
	gid := srcInfo.Sys().(*syscall.Stat_t).Gid
	err = os.Chown(dst, int(uid), int(gid))
	if err != nil {
		return fmt.Errorf("copyFile: Chown failed: %v", err)
	}

	return nil
}

// use dovecot API to replace original with modified, preserving original as backup
func (r *Rescan) replaceFile(index int, outputPathname string) error {

	messageId := r.MessageFiles[index].MessageId
	originalPathname := r.MessageFiles[index].Pathname
	newPathname, err := r.generateOutputPathname("new", index)

	var backupPathname string
	if viper.GetBool("rescan_backup_enabled") {
		backupPathname, err = r.generateOutputPathname("tmp/backup", index)
		if err != nil {
			return err
		}
	}

	if Verbose {
		log.Printf("BEGIN replaceFile [%d] %s %s\n", index, r.mailBox, messageId)
		log.Printf("original: %s\n", originalPathname)
		log.Printf("output: %s\n", outputPathname)
		log.Printf("backup: %s\n", backupPathname)
		log.Printf("new: %s\n", newPathname)
	}

	// backup the original message file if backup is configured
	if backupPathname != "" {
		if Verbose {
			log.Printf("backup: copying '%s' -> '%s'\n", originalPathname, backupPathname)
		}
		err = copyFile(backupPathname, originalPathname)
		if err != nil {
			return err
		}

	}

	// set the message \Deleted flag with dovecot
	err = r.doveadm.MessageDelete(r.username, r.mailBox, messageId)
	if err != nil {
		return err
	}

	// wait for dovecot to report the messageID is no longer present in MAILDIR
	err = r.awaitMessagePresent(messageId, false)
	if err != nil {
		return err
	}

	// create a hard link to the rescan output file in MAILDIR/new; dovecot will processes it
	err = os.Link(outputPathname, newPathname)
	if err != nil {
		return fmt.Errorf("failed linking '%s' -> '%s': %v", outputPathname, newPathname, err)
	}

	// wait for dovecot to report the messageID is present in MAILDIR
	err = r.awaitMessagePresent(messageId, true)
	if err != nil {
		return err
	}

	// remove the rescan output file from MAILDIR/tmp
	err = os.Remove(outputPathname)
	if err != nil {
		return fmt.Errorf("failed removing '%s': %v", outputPathname, err)
	}

	if Verbose {
		log.Printf("END replaceFile [%d] %s %s", index, r.mailBox, messageId)
	}

	delay := viper.GetInt64("rescan_sleep_seconds")
	if delay != 0 {
		time.Sleep(time.Duration(delay * int64(time.Second)))
	}

	// report success
	return nil
}

// wait for dovecot to delete or create a message
func (r *Rescan) awaitMessagePresent(messageId string, targetState bool) error {

	timeoutSeconds := viper.GetInt64("rescan_dovecot_timeout_seconds")

	if timeoutSeconds == 0 {
		return nil
	}

	delayTicks := viper.GetInt64("rescan_dovecot_delay_ms")

	timeout := time.After(time.Duration(timeoutSeconds * int64(time.Second)))
	ticker := time.NewTicker(time.Duration(delayTicks * int64(time.Millisecond)))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			present, err := r.doveadm.IsMessagePresent(r.username, r.mailBox, messageId)
			if err != nil {
				return fmt.Errorf("doveadm isMessagePresent failed: %v", err)
			}
			if present == targetState {
				return nil
			}
		case <-timeout:
			return fmt.Errorf("Timeout awaiting message presence change: %s %s %s", r.username, r.mailBox, messageId)
		}
	}
	return fmt.Errorf("logic error")
}

func generateNewBackupFilename(modified string) string {
	version := 0
	for {
		backup := fmt.Sprintf("%s.%d", modified, version)
		_, err := os.Stat(backup)
		if err != nil {
			return backup
		}
		version++
	}
}
