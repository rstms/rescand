package main

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

// path		    directory
// --------------   ------------------------------------
// INBOX	    /home/USER/Maildir/cur
// INBOX/folder	    /home/USER/Maildir/.INBOX.folder/cur
// INBOX/folder/sub /home/USER/Maildir/.INBOX.folder.sub/cur

func TestServerRescanMessage(t *testing.T) {
	InitializeTests(t)
	InitializeTestMaildir(t)
	request := RescanRequest{
		Username:   viper.GetString("test.email"),
		Folder:     viper.GetString("test.path"),
		MessageIds: []string{viper.GetString("test.message_id")},
	}
	rescan, err := NewRescan(&request)
	require.Nil(t, err)
	running := rescan.IsRunning()
	require.True(t, running)
	status := rescan.WaitStatus()
	fmt.Printf("status: %+v\n", status)
	require.False(t, status.Running)
	require.Equal(t, status.Total, 1)
	require.Equal(t, status.SuccessCount, 1)
	require.Equal(t, status.FailCount, 0)
}

func TestGenerateFilename(t *testing.T) {

	dir, err := os.MkdirTemp("", "test")
	require.Nil(t, err)
	defer os.RemoveAll(dir)
	name, err := generateImapPathname("testdata/cur/message", dir)
	require.Nil(t, err)
	require.NotEmpty(t, name)
	fmt.Printf("filename: %s\n", name)
}
