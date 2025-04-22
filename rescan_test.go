package main

import (
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"testing"
)

// path		    directory
// --------------   ------------------------------------
// INBOX	    /home/USER/Maildir/cur
// INBOX/folder	    /home/USER/Maildir/.INBOX.folder/cur
// INBOX/folder/sub /home/USER/Maildir/.INBOX.folder.sub/cur

func TestTransformPath(t *testing.T) {
	dir := transformPath("/home", "user1", "/INBOX", "cur")
	require.Equal(t, dir, "/home/user1/Maildir/cur")

	dir = transformPath("/home", "user2", "/INBOX/spam", "cur")
	require.Equal(t, dir, "/home/user2/Maildir/.INBOX.spam/cur")

	dir = transformPath("/home", "user3", "/test", "cur")
	require.Equal(t, dir, "/home/user3/Maildir/.test/cur")

	dir = transformPath("/home", "user4", "/lists/lists-personal/Advertising", "cur")
	require.Equal(t, dir, "/home/user4/Maildir/.lists.lists-personal.Advertising/cur")

	dir = transformPath("/tmp/rescan", "user5", "/lists/lists-personal/Advertising", "cur")
	require.Equal(t, dir, "/tmp/rescan/user5/Maildir/.lists.lists-personal.Advertising/cur")

	dir = transformPath("/tmp/rescan", "user6", "/lists/lists-personal/Advertising", "backup")
	require.Equal(t, dir, "/tmp/rescan/user6/Maildir/.lists.lists-personal.Advertising/backup")
}

func TestServerRescanMessage(t *testing.T) {
	InitializeTests(t)
	InitializeTestMaildir(t)
	email := viper.GetString("test.email")
	path := viper.GetString("test.path")
	messageId := viper.GetString("test.message_id")
	success, fail, err := Rescan(email, path, []string{messageId})
	require.Nil(t, err)
	require.Equal(t, success, 1)
	require.Equal(t, fail, 0)
}
