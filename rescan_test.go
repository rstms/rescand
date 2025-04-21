package main

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"testing"
)

// path		    directory
// --------------   ------------------------------------
// INBOX	    /home/USER/Maildir/cur
// INBOX/folder	    /home/USER/Maildir/.INBOX.folder/cur
// INBOX/folder/sub /home/USER/Maildir/.INBOX.folder.sub/cur

func TestTransformPath(t *testing.T) {
	dir := transformPath("/home", "user", "cur", "/INBOX")
	require.Equal(t, dir, "/home/user/Maildir/cur")

	dir = transformPath("/home", "user", "cur", "/INBOX/spam")
	require.Equal(t, dir, "/home/user/Maildir/.INBOX.spam/cur")

	dir = transformPath("/home", "user", "cur", "/test")
	require.Equal(t, dir, "/home/user/Maildir/.test/cur")

	dir = transformPath("/home", "user", "cur", "/lists/lists-personal/Advertising")
	require.Equal(t, dir, "/home/user/Maildir/.lists.lists-personal.Advertising/cur")

	dir = transformPath("/tmp/rescan", "user", "cur", "/lists/lists-personal/Advertising")
	require.Equal(t, dir, "/tmp/rescan/user/Maildir/.lists.lists-personal.Advertising/cur")

	dir = transformPath("/tmp/rescan", "user", "backup", "/lists/lists-personal/Advertising")
	require.Equal(t, dir, "/tmp/rescan/user/Maildir/.lists.lists-personal.Advertising/backup")
}

func TestRescanMessage(t *testing.T) {

	viper.SetConfigFile("testdata/rescan_test.yaml")
	err := viper.ReadInConfig()

	maildir := viper.GetString("test.maildir")
	email := viper.GetString("test.email")
	file := viper.GetString("test.file")
	messageId := viper.GetString("test.message_id")
	testPath := viper.GetString("test.path")

	fmt.Printf("maildir: %s\n", maildir)
	fmt.Printf("email: %s\n", email)
	fmt.Printf("file: %s\n", file)
	fmt.Printf("messageId: %s\n", messageId)
	fmt.Printf("testPath: %s\n", testPath)

	err = os.RemoveAll(maildir)
	require.Nil(t, err)
	err = os.MkdirAll(path.Join(maildir, "cur"), 0755)
	require.Nil(t, err)
	copyFile(path.Join(maildir, "cur", path.Base(file)), path.Join("testdata", file))
	success, fail, err := Rescan(email, testPath, []string{messageId})
	require.Nil(t, err)
	require.Equal(t, success, 1)
	require.Equal(t, fail, 0)
}
