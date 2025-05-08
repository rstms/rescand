package main

import (
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"testing"
)

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
	log.Printf("Commands: %v\n", commands)
	err = os.WriteFile("testdata/commands.json", []byte(commands), 0600)
	require.Nil(t, err)
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
	messageId := viper.GetString("test.flag_test_message_id")
	err = doveadm.MessageAddFlag(user, mailbox, messageId, "\\Seen")
	require.Nil(t, err)
}

func TestDoveadmSetUnseen(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	user := viper.GetString("test.email")
	mailbox := viper.GetString("test.dovecot_mailbox")
	messageId := viper.GetString("test.flag_test_message_id")
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

func TestDoveadmIsMailboxPresent(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	user := viper.GetString("test.email")
	mailbox := viper.GetString("test.dovecot_mailbox") + ".fnord"
	present, err := doveadm.IsMailboxPresent(user, mailbox)
	require.Nil(t, err)
	require.False(t, present)
	log.Printf("%v present: %v", mailbox, present)

	mailbox = viper.GetString("test.dovecot_mailbox") + ".rescan"
	present, err = doveadm.IsMailboxPresent(user, mailbox)
	require.Nil(t, err)
	require.True(t, present)
	log.Printf("%v present: %v", mailbox, present)
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

func TestDoveadmMailboxCreate(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	user := viper.GetString("test.email")
	mailbox := "howdy"
	err = doveadm.MailboxCreate(user, mailbox, true)
	require.Nil(t, err)
}

func TestDoveadmMessageMove(t *testing.T) {
	InitializeTests(t)
	doveadm, err := NewDoveadmClient()
	user := viper.GetString("test.email")
	dst := "howdy"
	src := viper.GetString("test.dovecot_mailbox")
	messageId := viper.GetString("test.move_test_message_id")
	err = doveadm.MessageMove(user, dst, src, messageId)
	require.Nil(t, err)
}
