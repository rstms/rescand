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

func TestServerRescanMessage(t *testing.T) {
	InitializeTests(t)
	InitializeTestMaildir(t)
	email := viper.GetString("test.email")
	path := viper.GetString("test.path")
	messageId := viper.GetString("test.message_id")
	rescan, err := NewRescan(email, path, []string{messageId})
	require.Nil(t, err)
	running := rescan.IsRunning()
	require.True(t, running)
	status := rescan.WaitStatus()
	require.False(t, status.Running)
	require.Equal(t, status.Total, 1)
	require.Equal(t, status.SuccessCount, 1)
	require.Equal(t, status.FailCount, 0)
}
