package main

import (
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"syscall"
	"testing"
	"time"
)

// path		    directory
// --------------   ------------------------------------
// INBOX	    /home/USER/Maildir/cur
// INBOX/folder	    /home/USER/Maildir/.INBOX.folder/cur
// INBOX/folder/sub /home/USER/Maildir/.INBOX.folder.sub/cur

func TestTransformPath(t *testing.T) {
	dir := transformPath("user", "/INBOX")
	require.Equal(t, dir, "/home/user/Maildir/cur")

	dir = transformPath("user", "/INBOX/spam")
	require.Equal(t, dir, "/home/user/Maildir/.INBOX.spam/cur")

	dir = transformPath("user", "/test")
	require.Equal(t, dir, "/home/user/Maildir/.test/cur")

	dir = transformPath("user", "/lists/lists-personal/Advertising")
	require.Equal(t, dir, "/home/user/Maildir/.lists.lists-personal.Advertising/cur")
}

func TestReplaceFile(t *testing.T) {

	// prepare test files
	err := os.RemoveAll("testdata/cur")
	require.Nil(t, err)
	err = os.Mkdir("testdata/cur", 0700)
	require.Nil(t, err)

	err = os.RemoveAll("testdata/rescan")
	require.Nil(t, err)
	err = os.Mkdir("testdata/rescan", 0700)
	require.Nil(t, err)

	reference, err := time.Parse(time.RFC3339, "2025-01-01T01:01:01-07:00")
	require.Nil(t, err)
	log.Printf("reference time: %s\n", reference.Format(time.RFC3339))

	original := "testdata/cur/file"
	modified := "testdata/rescan/file"
	err = os.WriteFile(original, []byte("original data\n"), 0644)
	require.Nil(t, err)

	err = os.WriteFile(modified, []byte("modified data\n"), 0644)
	require.Nil(t, err)

	err = os.Chtimes(original, time.Now(), reference)
	require.Nil(t, err)

	ostat, err := os.Stat(original)
	require.Nil(t, err)
	log.Printf("original time: %s\n", ostat.ModTime().Format(time.RFC3339))

	stat := ostat.Sys().(*syscall.Stat_t)
	ouid := stat.Uid
	ogid := stat.Gid

	require.Equal(t, ostat.ModTime(), reference, "expected original time to equal reference")

	// modified time differs from original and reference
	mstat, err := os.Stat(modified)
	require.Nil(t, err)
	log.Printf("modified time: %s\n", mstat.ModTime().Format(time.RFC3339))
	require.NotEqual(t, mstat.ModTime(), ostat.ModTime(), "expected modified time to differ from original")
	require.NotEqual(t, mstat.ModTime(), reference, "expected modified time to differ from reference")

	// backup does not exist before replaceFile
	backup := "testdata/rescan/file.bak"
	_, err = os.Stat(backup)
	require.NotNil(t, err, "expected backup to exist")

	messageFile := MessageFile{
		Pathname: original,
		Info:     ostat,
		UID:      ouid,
		GID:      ogid,
	}

	err = replaceFile(messageFile, modified, backup)
	require.Nil(t, err)

	// original has the same time, mode, uid, gid as before replaceFile call
	aostat, err := os.Stat(original)
	require.Nil(t, err)
	require.Equal(t, aostat.ModTime(), ostat.ModTime(), "expected original after replaceFile to have same time as original")
	require.Equal(t, aostat.ModTime(), reference, "expected original after replaceFile to have same time as reference")
	require.Equal(t, aostat.Mode(), ostat.Mode(), "expected original file mode bits unchanged after replaceFile")
	stat = aostat.Sys().(*syscall.Stat_t)
	aouid := stat.Uid
	aogid := stat.Gid
	require.Equal(t, aouid, messageFile.UID, "expected original uid unchanged after replaceFile")
	require.Equal(t, aogid, messageFile.GID, "expected original gid unchanged after replaceFile")

	// backup file contains original data
	backupContent, err := os.ReadFile(backup)
	require.Nil(t, err)
	require.Equal(t, string(backupContent), "original data\n", "expected original content in backup file")

	// backup has same time, mode, uid, gid as original
	bstat, err := os.Stat(backup)
	require.Nil(t, err)
	require.Equal(t, bstat.ModTime(), ostat.ModTime(), "expected backup to have same modtime as original")
	require.Equal(t, bstat.ModTime(), reference, "expected backup modtime to be reference")
	require.Equal(t, bstat.Mode(), ostat.Mode(), "expected backup to have same mode bits as original")
	stat = bstat.Sys().(*syscall.Stat_t)
	require.Equal(t, stat.Uid, messageFile.UID, "expected backup uid to match original")
	require.Equal(t, stat.Gid, messageFile.GID, "expected backup gid to match original")

	// original file now contains modified content
	newContent, err := os.ReadFile(original)
	require.Nil(t, err)
	require.Equal(t, string(newContent), "modified data\n", "expected original file to now contain modified content")

	// modified no loger exists
	_, err = os.Stat(modified)
	require.NotNil(t, err, "expected modified file not to exist")

}
