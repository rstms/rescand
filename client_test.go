package main

import (
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"log"
	"testing"
)

func TestScanBooks(t *testing.T) {
	InitializeTests(t)
	url := viper.GetString("filterctld_url")
	filterctl, err := NewAPIClient(url, nil)
	require.Nil(t, err)
	username := viper.GetString("test.email")
	books, err := filterctl.ScanAddressBooks(username, username)
	require.Nil(t, err)
	require.IsType(t, []string{}, books)
	log.Printf("books: %v\n", books)
}

func TestScanSpamClass(t *testing.T) {
	InitializeTests(t)
	url := viper.GetString("filterctld_url")
	filterctl, err := NewAPIClient(url, nil)
	require.Nil(t, err)
	username := viper.GetString("test.email")
	class, err := filterctl.ScanSpamClass(username, float32(900))
	require.Nil(t, err)
	require.Equal(t, "spam", class)
	log.Printf("class: %s\n", class)
}

func TestDoveadmRequest(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	require.Nil(t, err)
	params := make(map[string]interface{})
	params["string"] = "howdy"
	params["integer"] = 123
	params["stringSlice"] = []string{"foo", "moo", "goo"}
	params["intSlice"] = []int{1, 2, 3, 4}
	params["boolean"] = true
	id, request, err := doveadm.makeRequest("reload", &params)
	require.Nil(t, err)
	require.IsType(t, "", id)
	require.NotEmpty(t, id)
	require.IsType(t, []byte{}, request)
	require.NotEmpty(t, request)
	log.Printf("id: %s\n", id)
	log.Printf("request: %s\n", string(request))
}

func TestDoveadmCommands(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	require.Nil(t, err)
	commands, err := doveadm.getCommands()
	require.Nil(t, err)
	log.Println(commands)
}

func TestDoveadmBadCommand(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	require.Nil(t, err)
	responses, err := doveadm.sendCommand("howdy", nil)
	log.Printf("responses: %v\n", responses)
	log.Printf("err; %v\n", err)
	require.NotNil(t, err)
}

func TestDoveadmReload(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	require.Nil(t, err)
	err = doveadm.Reload()
	require.Nil(t, err)
}

func TestDoveadmMailboxList(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	require.Nil(t, err)
	list, err := doveadm.MailboxList(viper.GetString("test.email"))
	require.Nil(t, err)
	require.IsType(t, &[]string{}, list)
	for _, mailbox := range *list {
		log.Println(mailbox)
	}
}

func TestDoveadmSetSeen(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	user := viper.GetString("test.email")
	mailbox := viper.GetString("test.dovecot_mailbox")
	messageId := viper.GetString("test.message_id")
	err = doveadm.MessageAddFlag(user, mailbox, messageId, "\\Seen")
	require.Nil(t, err)
}

func TestDoveadmSetUnseen(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	user := viper.GetString("test.email")
	mailbox := viper.GetString("test.dovecot_mailbox")
	messageId := viper.GetString("test.message_id")
	err = doveadm.MessageRemoveFlag(user, mailbox, messageId, "\\Seen")
	require.Nil(t, err)
}

func TestDoveadmDeleteMessage(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	user := viper.GetString("test.email")
	mailbox := viper.GetString("test.dovecot_mailbox")
	messageId := viper.GetString("test.message_id")
	err = doveadm.MessageDelete(user, mailbox, messageId)
	require.Nil(t, err)
}

func TestDoveadmIsMessagePresent(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	user := viper.GetString("test.email")
	mailbox := viper.GetString("test.dovecot_mailbox")
	messageId := viper.GetString("test.message_id")
	present, err := doveadm.IsMessagePresent(user, mailbox, messageId)
	require.Nil(t, err)
	require.True(t, present)

	notPresent, err := doveadm.IsMessagePresent(user, mailbox, "notavalidmessageid")
	require.Nil(t, err)
	require.False(t, notPresent)
}
