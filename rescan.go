package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/emersion/go-message/textproto"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
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
	To        string
	From      string
	Subject   string
	Date      string
}

type RescanRequest struct {
	Username   string
	Folder     string
	MessageIds []string
}

type RescanError struct {
	Message  string
	Pathname string
	Headers  map[string]string
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
	Errors       []RescanError
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
	Status                RescanStatus
	MessageFiles          []MessageFile
	mutex                 sync.Mutex
	filterctl             *APIClient
	doveadm               *DoveadmClient
	username              string
	mailBox               string
	mailDir               string
	outBox                string
	outDir                string
	sieveFilter           string
	sieveScript           string
	wg                    sync.WaitGroup
	verbose               bool
	debug                 bool
	backupEnabled         bool
	subscribeRescan       bool
	dovecotDelayMs        int64
	dovecotTickerMs       int64
	dovecotTimeoutSeconds int64
	sleepSeconds          int64
}

var jobs sync.Mutex
var RescanJobs map[string]*Rescan

func setViperDefaults() {
	viper.SetDefault("max_active", 8)
	viper.SetDefault("dovecot_timeout_seconds", 30)
	viper.SetDefault("dovecot_delay_ms", 200)
	viper.SetDefault("dovecot_ticker_ms", 1000)
	viper.SetDefault("backup_enabled", false)
	viper.SetDefault("prune_seconds", 300)
	viper.SetDefault("sleep_seconds", 0)
	viper.SetDefault("subscribe_rescan", true)
	viper.SetDefault("sieve_filter", "/usr/local/bin/sieve-filter")
	viper.SetDefault("sieve_script", "/usr/local/lib/dovecot/sieve/new-mail.sieve")
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
			Errors:  make([]RescanError, 0),
		},
		MessageFiles:          make([]MessageFile, 0),
		verbose:               viper.GetBool("verbose"),
		debug:                 viper.GetBool("debug"),
		backupEnabled:         viper.GetBool("backup_enabled"),
		subscribeRescan:       viper.GetBool("subscribe_rescan"),
		sieveFilter:           viper.GetString("sieve_filter"),
		sieveScript:           viper.GetString("sieve_script"),
		sleepSeconds:          viper.GetInt64("sleep_seconds"),
		dovecotDelayMs:        viper.GetInt64("dovecot_delay_ms"),
		dovecotTickerMs:       viper.GetInt64("dovecot_ticker_ms"),
		dovecotTimeoutSeconds: viper.GetInt64("dovecot_timeout_seconds"),
	}
	rescan.Status.Request = request.Copy()

	username, _, found := strings.Cut(request.Username, "@")
	if !found {
		return nil, fmt.Errorf("failed parsing emailAddress: %s", request.Username)
	}
	rescan.username = username

	var err error

	rescan.filterctl, err = NewFilterctlClient()
	if err != nil {
		return nil, err
	}

	rescan.doveadm, err = NewDoveadmClient()
	if err != nil {
		return nil, err
	}

	err = rescan.setMaildir()
	if err != nil {
		return nil, err
	}

	err = rescan.createRescanMailbox()
	if err != nil {
		return nil, fmt.Errorf("CreateRescanMailbox: %v", err)
	}

	err = rescan.scanMessageFiles()
	if err != nil {
		return nil, err
	}

	func() {
		jobs.Lock()
		defer jobs.Unlock()
		if RescanJobs == nil {
			if rescan.verbose {
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

	maxActive := viper.GetInt("max_active")

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
						if r.verbose {
							log.Printf("RescanMessage[%d] started\n", index)
						}
						var result RescanResult
						result.index = index
						result.err = r.rescanMessage(index)
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
							if r.verbose {
								log.Printf("Rescan[%d] Succeeded: %s\n", result.index, r.Status.LatestFile)
							}
						} else {
							r.Status.FailCount++
							rescanError := RescanError{
								Message:  fmt.Sprintf("%v", result.err),
								Pathname: r.MessageFiles[result.index].Pathname,
								Headers: map[string]string{
									"Date":      r.MessageFiles[result.index].Date,
									"To":        r.MessageFiles[result.index].To,
									"From":      r.MessageFiles[result.index].From,
									"Subject":   r.MessageFiles[result.index].Subject,
									"Mesage-Id": r.MessageFiles[result.index].MessageId,
								},
							}
							r.Status.Errors = append(r.Status.Errors, rescanError)
							log.Printf("Rescan[%d] failed: %+v\n", result.index, rescanError)

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

		err := r.importMessages()
		if err != nil {
			r.mutex.Lock()
			r.Status.Errors = append(r.Status.Errors, RescanError{Message: fmt.Sprintf("Failed importing messages: %v", err)})
			r.mutex.Unlock()
		}

		err = r.deleteRescanMailbox()
		if err != nil {
			r.mutex.Lock()
			r.Status.Errors = append(r.Status.Errors, RescanError{Message: fmt.Sprintf("Failed deleting rescan mailbox: %v", err)})
			r.mutex.Unlock()
		}

		r.mutex.Lock()
		r.Status.Running = false
		r.doveadm = nil
		r.filterctl = nil
		r.mutex.Unlock()

		// setup a prune job to delete us out of RescanJobs after a while
		go func(rescanId string) {
			pruneSeconds := viper.GetInt64("prune_seconds")
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
		r.outBox = "INBOX.rescan"
		r.outDir = filepath.Join(MAILDIR_ROOT, r.username, "Maildir", ".INBOX.rescan")
	} else {
		dir := strings.ReplaceAll(r.Status.Request.Folder, "/", ".")
		if len(dir) < 2 {
			return fmt.Errorf("maildir too short: %s", dir)
		}
		r.mailBox = dir[1:]
		r.mailDir = filepath.Join(MAILDIR_ROOT, r.username, "Maildir", dir)
		r.outBox = r.mailBox + ".rescan"
		r.outDir = filepath.Join(MAILDIR_ROOT, r.username, "Maildir", dir+".rescan")
	}

	stat, err := os.Stat(r.mailDir)
	if err != nil {
		return fmt.Errorf("Maildir stat '%s' failed: %v", r.mailDir, err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("Maildir is not a directory: %s", r.mailDir)
	}

	if r.verbose {
		log.Printf("setMaildir: folder=%s mailbox=%s maildir=%s\n", r.Status.Request.Folder, r.mailBox, r.mailDir)
	}
	return nil
}

func (r *Rescan) createRescanMailbox() error {
	if r.verbose {
		log.Printf("Creating rescan maildir %s...", r.outDir)
	}
	err := r.doveadm.MailboxCreate(r.username, r.outBox, false, r.subscribeRescan)
	if err != nil {
		return fmt.Errorf("MailboxCreate failed: %v", err)
	}
	return nil
}

func (r *Rescan) deleteRescanMailbox() error {
	if r.verbose {
		log.Printf("Deleting rescan maildir %s...", r.outDir)
	}
	err := r.doveadm.MailboxDelete(r.username, r.outBox, true)
	if err != nil {
		return fmt.Errorf("MailboxDelete failed: %v", err)
	}
	return nil
}

func (r *Rescan) importMessages() error {

	if r.verbose {
		log.Printf("Importing rescanned messages from %s", r.outDir)
	}
	// /usr/local/bin/sieve-filter -e -W -u ${user} -m ${mailbox} ${sieve_script} ${mailbox}.rescan
	args := []string{}
	if r.verbose {
		args = append(args, "-v")
	}
	args = append(args, []string{"-e", "-W", "-u", r.username, "-m", r.mailBox, r.sieveScript, r.outBox}...)
	cmd := exec.Command(r.sieveFilter, args...)
	cmdLine := fmt.Sprintf("%s %s", cmd.Path, strings.Join(cmd.Args, " "))
	if r.verbose {
		log.Printf("sieve-filter command: %s\n", cmdLine)
	}
	var oBuf, eBuf bytes.Buffer
	cmd.Stdout = &oBuf
	cmd.Stderr = &eBuf
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("Failed executing sieve-filter command: %v", err)
	}
	exitCode := cmd.ProcessState.ExitCode()

	if exitCode != 0 {
		log.Printf("Error: sieve filter command exited %d\n", cmd.ProcessState.ExitCode())
		log.Printf("command: %s\n", cmdLine)
	}

	if r.verbose || exitCode != 0 {
		logLines("stdout", oBuf.String())
	}

	if exitCode != 0 {
		logLines("stderr", eBuf.String())
		return fmt.Errorf("sieve-filter import exited %d: %s\n", cmd.ProcessState.ExitCode(), eBuf.String())
	}
	return nil
}

func logLines(label, output string) {
	for _, line := range strings.Split(output, "\n") {
		log.Printf("%s: %s\n", label, line)
	}
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
				if hasTrashFlag(pathname) {
					continue
				}
				mid, err := r.getMessageId(pathname)
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
				if hasTrashFlag(pathname) {
					continue
				}
				mid, err := r.getMessageId(pathname)
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
	if r.verbose {
		log.Printf("scanMessageFiles: dir=%s count=%d \n", dir, len(r.MessageFiles))
		for i, messageFile := range r.MessageFiles {
			log.Printf("  [%d] %+v\n", i, messageFile)
		}
	}
	return nil
}

// detect message filenames with IMAP \Trash flag
func hasTrashFlag(pathname string) bool {
	_, flags, found := strings.Cut(pathname, ":2,")
	if found {
		if strings.ContainsRune(flags, 'T') {
			return true
		}
	}
	return false
}

func (r *Rescan) getMessageId(pathname string) (string, error) {
	file, err := os.Open(pathname)
	if err != nil {
		return "", fmt.Errorf("failed opening file %s: %v", pathname, err)
	}
	defer file.Close()
	header, err := textproto.ReadHeader(bufio.NewReader(file))
	if err != nil {
		return "", fmt.Errorf("textproto.ReadHeader failed: %v", err)
	}
	mid := header.Get("Message-Id")
	mid = strings.TrimSpace(mid)
	mid = strings.TrimLeft(mid, "<")
	mid = strings.TrimRight(mid, ">")
	mid = strings.TrimSpace(mid)
	if len(mid) == 0 {
		log.Printf("WARNING: missing Message-Id header: %s\n", pathname)
	}
	if r.debug {
		log.Printf("getMessageId returning: %s\n", mid)
	}
	return mid, nil
}

func (r *Rescan) rescanMessage(index int) error {

	inputPathname := r.MessageFiles[index].Pathname
	if r.verbose {
		log.Printf("rescanMessage[%d] reading input file: %s\n", index, inputPathname)
	}
	content, err := os.ReadFile(inputPathname)
	if err != nil {
		return fmt.Errorf("failed reading input file %s: %v", inputPathname, err)
	}
	lines := strings.Split(string(content), "\n")

	if r.debug {
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
		return fmt.Errorf("textproto.ReadHeader failed reading input file headers: %v", err)
	}

	mid := headers.Get("Message-Id")
	mid = strings.TrimLeft(mid, "<")
	mid = strings.TrimRight(mid, ">")
	if mid != r.MessageFiles[index].MessageId {
		return fmt.Errorf("MessageId mismatch; expected '%s' but got '%s' %+v", r.MessageFiles[index].MessageId, mid, r.MessageFiles[index])
	}

	r.MessageFiles[index].Subject = headers.Get("Subject")
	r.MessageFiles[index].Date = headers.Get("Date")

	fromAddr, err := r.parseHeaderAddr(index, &headers, "From")
	if err != nil {
		return fmt.Errorf("parseHeaderAddr: %v", err)
	}
	r.MessageFiles[index].From = fromAddr

	rcptToAddr, err := r.parseHeaderAddr(index, &headers, "To")
	if err != nil {
		return fmt.Errorf("parseHeaderAddr: %v", err)
	}

	deliveredToAddr, err := r.parseDeliveredToAddr(index, &headers)
	if err != nil {
		return fmt.Errorf("parseDeliveredToAddAddr: %v", err)
	}

	if r.MessageFiles[index].To == "" {
		r.MessageFiles[index].To = deliveredToAddr
	}

	senderIP, err := r.getSenderIP(index, &headers)
	if err != nil {
		return fmt.Errorf("getSenderIP: %v", err)
	}

	var response RspamdResponse
	err = r.requestRescan(index, fromAddr, rcptToAddr, deliveredToAddr, senderIP, &content, &response)
	if err != nil {
		return fmt.Errorf("requestRescan: %v", err)
	}

	err = r.mungeHeaders(index, &headers, fromAddr, senderIP, &response, &keys)
	if err != nil {
		return fmt.Errorf("mungeHeaders: %v", err)
	}

	if r.debug {
		log.Println("---BEGIN CHANGED HEADERS---")
		fields := headers.Fields()
		for fields.Next() {
			data, err := fields.Raw()
			if err != nil {
				fmt.Errorf("fields.Raw failed: %v", err)
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

	outputPathname, err := r.generateOutputPathname(r.outDir, "tmp", index)
	if err != nil {
		return fmt.Errorf("generateOutputPathname: %v", err)
	}

	if r.verbose {
		log.Printf("rescanMessage[%d] writing output file: %s\n", index, outputPathname)
	}

	err = func() error {
		outfile, err := os.Create(outputPathname)
		if err != nil {
			return fmt.Errorf("os.Create failed creating output file '%s': %v", outputPathname, err)
		}
		defer outfile.Close()

		fields := headers.Fields()
		for fields.Next() {
			data, err := fields.Raw()
			if err != nil {
				fmt.Errorf("fields.Raw failed reading header: %v", err)
			}
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
			_, err = fmt.Fprintf(outfile, "%s", string(data))
			if err != nil {
				fmt.Errorf("Fprintf failed writing header line '%+v': %v", data, err)
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
				fmt.Errorf("Fprintf failed writing body line: %v", err)
			}
		}
		return nil
	}()

	if err != nil {
		return err
	}

	err = r.chownPath(outputPathname)
	if err != nil {
		return fmt.Errorf("chownPath failed on output file '%s': %v", outputPathname, err)
	}

	err = r.replaceFile(index, outputPathname)
	if err != nil {
		return fmt.Errorf("replaceFile: %v", err)
	}
	return nil
}

func (r *Rescan) requestRescan(index int, fromAddr, rcptToAddr, deliveredToAddr, senderIP string, content *[]byte, response *RspamdResponse) error {

	requestHeaders := map[string]string{
		"settings": `{"symbols_disabled": ["DATE_IN_PAST", "SPAM_FLAG"]}`,
		"IP":       senderIP,
		"From":     fromAddr,
		"Rcpt":     rcptToAddr,
		"Hostname": viper.GetString("hostname"),
	}

	if deliveredToAddr != "" {
		requestHeaders["Delivered-To"] = deliveredToAddr
	}

	_, err := r.filterctl.Post("/rspamc/checkv2", content, response, &requestHeaders)
	if err != nil {
		return fmt.Errorf("rspamd check request failed: %v", err)
	}

	if r.debug {

		for name := range response.Milter.RemoveHeaders {
			log.Printf("requestRescan[%d] remove: %s\n", index, name)
		}

		for name, _ := range response.Milter.AddHeaders {
			log.Printf("requestRescan[%d] add: %s\n", index, name)
		}
	}
	return nil
}

func (r *Rescan) mungeHeaders(index int, headers *textproto.Header, fromAddr, senderIP string, response *RspamdResponse, keys *[]string) error {

	// delete headers RSPAM wants to delete
	for key, _ := range response.Milter.RemoveHeaders {
		headers.Del(key)
	}

	deleteHeaders := []string{
		"x-address-book",
		"x-senderscore",
		"x-spam",
		"x-rspam",
		"x-rescanned",
		"x-sieve-filtered",
	}
	// delete headers if present
	for _, key := range *keys {
		for _, deleteHeader := range deleteHeaders {
			if strings.HasPrefix(strings.ToLower(key), deleteHeader) {
				headers.Del(key)
			}
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
			if r.debug {
				log.Printf("mungeHeaders[%d] adding: '%s': '%s'\n", index, key, value.Value)
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
	if r.debug {
		log.Printf("mungeHeaders[%d] adding: X-Spam-Status: %s\n", index, spamStatus)
	}

	spamScore := fmt.Sprintf("%.3f / %.3f", response.Score, response.Required)
	headers.Set("X-Spam-Score", spamScore)
	if r.debug {
		log.Printf("mungeHeaders[%d] adding: X-Spam-Score: %s\n", index, spamScore)

	}

	senderScore, err := r.getSenderScore(index, senderIP)
	if err != nil {
		log.Printf("mungeHeaders[%d] WARNING: senderscore lookup failed: %v", index, err)
	} else {
		headers.Set("X-SenderScore", fmt.Sprintf("%d", senderScore))
		if r.debug {
			log.Printf("mungeHeaders[%d] adding: X-SenderScore: %d\n", index, senderScore)
		}

	}

	books, err := r.filterctl.ScanAddressBooks(r.Status.Request.Username, fromAddr)
	if err != nil {
		return fmt.Errorf("filterctl ScanAddressBooks request failed: %v", err)
	}
	addressBookValue := strings.Join(books, ",")
	//for _, book := range books {
	//bookAsEmail := fmt.Sprintf("%s <%s@addresss.book.filter>", book, book)
	headers.Add("X-Address-Book", addressBookValue)
	if r.verbose {
		log.Printf("mungeHeaders[%d] adding: X-Address-Book: %s\n", index, addressBookValue)
	}
	//}

	class, err := r.filterctl.ScanSpamClass(r.Status.Request.Username, response.Score)
	if err != nil {
		return fmt.Errorf("filterctl ScanSpamClass request failed: %v", err)
	}
	headers.Set("X-Spam-Class", class)
	if r.verbose {
		log.Printf("mungeHeaders[%d] adding: X-Spam-Class: %s\n", index, class)
	}

	var spamValue string
	if class == "spam" {
		spamValue = "yes"
	} else {
		spamValue = "no"
	}
	headers.Set("X-Spam", spamValue)
	if r.verbose {
		log.Printf("mungeHeaders[%d] adding: X-Spam: %s\n", index, spamValue)
	}

	headers.Set("X-Rescanned", "yes")

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

func (r *Rescan) parseHeaderAddr(index int, header *textproto.Header, key string) (string, error) {
	value := header.Get(key)
	if value == "" {
		return "", fmt.Errorf("header not found: %s", key)
	}
	emailAddress, err := parseEmailAddress(value)
	if err != nil {
		return "", fmt.Errorf("failed parsing email address from header '%s': %v", key, err)
	}
	if r.debug {
		log.Printf("parseHeaderAddr[%d] returning: %s\n", index, emailAddress)
	}
	return emailAddress, nil
}

func (r *Rescan) parseDeliveredToAddr(index int, header *textproto.Header) (string, error) {
	key := "Delivered-To"
	for _, value := range header.Values(key) {
		if strings.ContainsRune(value, '@') {
			emailAddress, err := parseEmailAddress(value)
			if err != nil {
				return "", err
			}
			return emailAddress, nil
		}
	}
	return "", fmt.Errorf("no email address header value found: %s", key)
}

func (r *Rescan) getSenderIP(index int, header *textproto.Header) (string, error) {
	received := header.Values("Received")
	if len(received) < 2 {
		return "", fmt.Errorf("insufficient Received headers")
	}
	match := IP_ADDR_PATTERN.FindStringSubmatch(received[1])
	if len(match) < 2 {
		return "", fmt.Errorf("failed parsing IP address from: '%s'", received[1])
	}
	addr := match[1]
	if r.debug {
		log.Printf("getSenderIP[%d] returning: %s\n", index, addr)
	}
	return addr, nil
}

func (r *Rescan) getSenderScore(index int, addr string) (int, error) {
	octets := strings.Split(addr, ".")
	if len(octets) != 4 {
		return 0, fmt.Errorf("Invalid sender IP: %v", addr)
	}
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
	if r.debug {
		log.Printf("getSenderScore[%d] for %s returning: %d\n", index, addr, score)
	}
	return score, nil
}

func (r *Rescan) generateOutputPathname(dir, sub string, index int) (string, error) {

	outDir := filepath.Join(dir, sub)

	_, err := os.Stat(outDir)
	if err != nil {
		err := os.MkdirAll(outDir, 0700)
		if err != nil {
			return "", fmt.Errorf("os.MkdirAll failed creating '%s': %v", outDir, err)
		}
		err = r.chownPath(outDir)
		if err != nil {
			return "", fmt.Errorf("chownPath failed setting ownership of '%s': %v", outDir, err)
		}
	}

	fileName := path.Base(r.MessageFiles[index].Pathname)
	var outputPath string
	if sub == "tmp/backup" {
		// we're generating the backup pathname, so ensure no clobber
		outputPath = generateNewBackupFilename(filepath.Join(outDir, fileName))
	} else {
		// we're generating the rescan output pathname, so strip the filename metadata
		// FIXME: should we preserve the flags portion and regenerate the S=XXXX,W=XXXX size metadata?
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
		return fmt.Errorf("stat failed on src '%s': %v", src, err)
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed opening src '%s': %v", src, err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed creating dst '%s': %v", dst, err)
	}
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("data copy from %s to %s failed: %v", src, dst, err)
	}
	dstFile.Close()

	// replicate access mode bits
	err = os.Chmod(dst, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("mode change failed on dst '%s': %v", dst, err)
	}

	// replicate modification time
	err = os.Chtimes(dst, time.Now(), srcInfo.ModTime())
	if err != nil {
		return fmt.Errorf("modification time change failed on dst '%s': %v", dst, err)
	}

	// replicate ownership
	uid := srcInfo.Sys().(*syscall.Stat_t).Uid
	gid := srcInfo.Sys().(*syscall.Stat_t).Gid
	err = os.Chown(dst, int(uid), int(gid))
	if err != nil {
		return fmt.Errorf("ownership change failed on dst '%s': %v", dst, err)
	}

	return nil
}

// delete original, await dovecot expunge, move modified file to rescan/new, await dovecot import
func (r *Rescan) replaceFile(index int, outputPathname string) error {

	messageId := r.MessageFiles[index].MessageId
	originalPathname := r.MessageFiles[index].Pathname

	newPathname, err := generateImapPathname(outputPathname, filepath.Join(r.outDir, "new"))
	if err != nil {
		return fmt.Errorf("generateImapPathname: %v", err)
	}

	var backupPathname string
	if r.backupEnabled {
		backupPathname, err = r.generateOutputPathname(r.mailDir, "tmp/backup", index)
		if err != nil {
			return fmt.Errorf("generateOutputPathname failed on backup pathname: %v", err)

		}
	}

	if r.verbose {
		log.Printf("replaceFile[%d] mailbox: %s\n", index, r.mailBox)
		log.Printf("replaceFile[%d] messageId: %s\n", index, messageId)
		log.Printf("replaceFile[%d] original: %s\n", index, originalPathname)
		log.Printf("replaceFile[%d] output: %s\n", index, outputPathname)
		log.Printf("replaceFile[%d] backup: %s\n", index, backupPathname)
		log.Printf("replaceFile[%d] new: %s\n", index, newPathname)
	}

	// backup the original message file if backup is configured
	if backupPathname != "" {
		if r.verbose {
			log.Printf("replaceFile[%d]: copying '%s' to '%s'\n", index, originalPathname, backupPathname)
		}
		err = copyFile(backupPathname, originalPathname)
		if err != nil {
			return fmt.Errorf("copyFile failed copying original to backup: %v", err)
		}

	}

	// set the message \Deleted flag with dovecot
	if r.verbose {
		log.Printf("replaceFile[%d] requesting dovecot original delete: %s %s %s\n", index, r.username, r.mailBox, messageId)
	}
	err = r.doveadm.MessageDelete(r.username, r.mailBox, messageId)
	if err != nil {
		return fmt.Errorf("dovecot MessageDelete request failed on original file: %s %s %s: %v", r.username, r.mailBox, messageId, err)
	}

	if r.verbose {
		log.Printf("replaceFile[%d] awaiting dovecot current message expunge...\n", index)
	}

	// wait for dovecot to report the messageID is no longer present in MAILDIR
	err = r.dovecotWait(r.mailBox, messageId, false)
	if err != nil {
		return fmt.Errorf("dovecotWait failed awaiting original message removal from cur: %v", err)
	}

	if r.verbose {
		log.Printf("replaceFile[%d] moving output to new: '%s' to '%s'\n", index, outputPathname, newPathname)
	}

	// move the rescan output file to MAILDIR.rescan/new; dovecot will processes it
	err = os.Rename(outputPathname, newPathname)
	if err != nil {
		return fmt.Errorf("Rename failed moving '%s' to '%s': %v", outputPathname, newPathname, err)
	}

	if r.verbose {
		log.Printf("replaceFile[%d] awaiting dovecot new message import...\n", index)
	}

	// wait for dovecot to report the messageID is present in MAILDIR.rescan/cur
	err = r.dovecotWait(r.outBox, messageId, true)
	if err != nil {
		return fmt.Errorf("dovecotWait failed awaiting new message import to cur: %v", err)
	}

	if r.sleepSeconds != 0 {
		log.Printf("replaceFile[%d] WARNING sleeping %d seconds (rescan.sleep_seconds)\n", index, r.sleepSeconds)
		time.Sleep(time.Duration(r.sleepSeconds * int64(time.Second)))
	}

	if r.verbose {
		log.Printf("replaceFile[%d] success %s %s %s", index, r.username, r.mailBox, messageId)
	}

	// report success
	return nil
}

func (r *Rescan) checkPresence(mailBox, messageId string, targetState bool) (bool, error) {
	present, err := r.doveadm.IsMessagePresent(r.username, mailBox, messageId)
	if err != nil {
		return false, fmt.Errorf("doveadm.isMessagePresent request failed %s %s %s:  %v", r.username, mailBox, messageId, err)
	}
	if present == targetState {
		return true, nil
	}
	return false, nil
}

// wait for dovecot to delete or create a message
func (r *Rescan) dovecotWait(mailBox, messageId string, targetState bool) error {

	timeout := time.After(time.Duration(r.dovecotTimeoutSeconds) * time.Second)
	delay := time.After(time.Duration(r.dovecotDelayMs) * time.Millisecond)
	ticker := time.NewTicker(time.Duration(r.dovecotTickerMs) * time.Millisecond)
	defer ticker.Stop()

	var count int
	for {
		select {
		case <-delay:
			done, err := r.checkPresence(mailBox, messageId, targetState)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		case <-ticker.C:
			count++
			done, err := r.checkPresence(mailBox, messageId, targetState)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
			break
		case <-timeout:
			return fmt.Errorf("Timed out after %d seconds", r.dovecotTimeoutSeconds)
		}
	}
	panic("unreachable")
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
	panic("unreachable")
}

func generateImapPathname(tempFile, outDir string) (string, error) {
	now := time.Now()
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed getting hostname: %v", err)
	}
	micros := now.Nanosecond() / 1000
	name := fmt.Sprintf("%d.M%dP%d.%s", now.Unix(), micros, os.Getpid(), hostname)
	/*
		stat, err := os.Stat(tempFile)
		if err != nil {
			return "", fmt.Errorf("Stat failed: %v", err)
		}
		file, err := os.Open(tempFile)
		if err != nil {
		    return "", fmt.Errorf("Open failed: %v", err)
		}
		defer file.Close()
		var lines int64
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
		    lines += 1
		}
		err = scanner.Err()
		if err != nil {
		    return "", fmt.Errorf("failed scanning temp file: %v", err)
		}
		name = fmt.Sprintf("%s,S=%d,W=%d", name, stat.Size(), stat.Size()+lines)
	*/
	pathName := filepath.Join(outDir, name)
	_, err = os.Stat(pathName)
	if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("file existence Stat failed: %v", err)
	}
	return pathName, nil
}
