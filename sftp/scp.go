package sftp

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	ssh3 "github.com/h4sh5/sshoq"
	"github.com/h4sh5/sshoq/client"
)

// RunScpClient performs a single non-interactive copy between the local
// machine and the remote host, reusing the SFTP channel and its request
// protocol (the same channel the interactive -sftp mode uses). upload selects
// the direction: when true, localPath is copied to remotePath; when false,
// remotePath is copied to localPath. recursive enables directory transfers.
// A remote path of "" or "~" (and a "~/" prefix) targets the remote user's home
// directory, like scp's "host:" and "host:~/".
//
// While the copy runs, SIGINT (Ctrl+C) and SIGTERM cancel it: the transfer
// stops at the next chunk boundary, partial local files are removed, and
// ErrCancelled is returned.
func RunScpClient(c *client.Client, upload bool, recursive bool, localPath, remotePath string) error {
	channel, err := c.OpenChannel("sftp", 30000, 0)
	if err != nil {
		return fmt.Errorf("could not open sftp channel: %w", err)
	}
	defer channel.Close()
	if err := channel.WaitOpen(); err != nil {
		return fmt.Errorf("could not open sftp channel: %w", err)
	}

	// Resolve the home-directory forms of the remote path before transferring;
	// an explicit remote path needs no request and is left as it is.
	remotePath, err = resolveScpRemotePath(channel, remotePath)
	if err != nil {
		return err
	}

	// Scp mode runs with a normal terminal, so Ctrl+C is delivered as SIGINT
	// and cancels the transfer instead of killing the process mid-copy.
	cancel := &transferCancel{}
	stop := watchSignals(cancel)
	defer stop()

	if upload {
		return scpUpload(channel, recursive, localPath, remotePath, cancel)
	}
	return scpDownload(channel, recursive, remotePath, localPath, cancel)
}

// scpUpload copies a local file or directory to the remote host. Mirroring
// scp semantics, when the remote target is an existing directory or ends with
// a path separator, the source is copied into it under its own basename
// (e.g. `scp -r ./dir host:/tmp/` copies to /tmp/dir).
func scpUpload(channel ssh3.Channel, recursive bool, localPath, remotePath string, cancel *transferCancel) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("cannot stat local path %s: %w", localPath, err)
	}
	if info.IsDir() && !recursive {
		return fmt.Errorf("cannot upload directory %s: use -r for recursive copy", localPath)
	}

	if strings.HasSuffix(remotePath, "/") {
		remotePath = path.Join(remotePath, filepath.Base(localPath))
	} else if isRemoteDir(channel, remotePath) {
		remotePath = path.Join(remotePath, filepath.Base(localPath))
	}

	if recursive {
		return uploadRecursive(channel, localPath, remotePath, true, cancel)
	}
	return uploadFile(channel, localPath, remotePath, true, cancel)
}

// scpDownload copies a remote file or directory to the local machine.
// Mirroring scp semantics, when the local target is an existing directory or
// ends with a path separator, the remote source is copied into it under its
// own basename (e.g. `scp -r host:/etc/nginx .` copies to ./nginx).
func scpDownload(channel ssh3.Channel, recursive bool, remotePath, localPath string, cancel *transferCancel) error {
	info, err := os.Stat(localPath)
	if err == nil && info.IsDir() {
		localPath = filepath.Join(localPath, filepath.Base(remotePath))
	} else if strings.HasSuffix(localPath, string(filepath.Separator)) {
		localPath = filepath.Join(localPath, filepath.Base(remotePath))
	}

	if recursive {
		return downloadRecursive(channel, remotePath, localPath, true, cancel)
	}
	return downloadFile(channel, remotePath, localPath, true, cancel)
}

// remoteHomeDir asks the server for the current directory of the SFTP session.
// The server always starts a session in the authenticated user's home
// directory, so the answer is that user's home, which is what scp's "host:"
// refers to.
func remoteHomeDir(channel ssh3.Channel) (string, error) {
	resp, err := doRequest(channel, &Request{Cmd: "pwd"})
	if err != nil {
		return "", fmt.Errorf("could not determine the remote home directory: %w", err)
	}
	if !resp.OK || resp.Path == "" {
		msg := resp.Error
		if msg == "" {
			msg = "the server did not report its current directory"
		}
		return "", fmt.Errorf("could not determine the remote home directory: %s", msg)
	}
	return resp.Path, nil
}

// resolveScpRemotePath resolves the remote side of an scp-style copy. The empty
// path (user@host:443/sshoq-server%) and the "~"/"~/" forms mean the remote
// user's home directory, like OpenSSH scp's "host:", "host:~" and "host:~/dir";
// they are replaced with the home directory reported by the server. Every other
// path is returned unchanged, so absolute paths stay absolute and relative ones
// keep resolving against the session's directory (the home) on the server.
// A trailing separator is kept: "host%~/" names the home directory itself as a
// directory target, so the source basename is appended to it.
func resolveScpRemotePath(channel ssh3.Channel, remotePath string) (string, error) {
	if remotePath != "" && remotePath != "~" && !strings.HasPrefix(remotePath, "~/") {
		return remotePath, nil
	}
	home, err := remoteHomeDir(channel)
	if err != nil {
		return "", err
	}
	if remotePath == "" {
		return home, nil
	}
	expanded := expandTildePath(remotePath, home)
	if strings.HasSuffix(remotePath, "/") && expanded != "/" && !strings.HasSuffix(expanded, "/") {
		expanded += "/"
	}
	return expanded, nil
}

// isRemoteDir reports whether the remote path refers to an existing
// directory. Errors (including a missing path) are reported as "not a
// directory" so callers fall back to treating the target as a file name.
func isRemoteDir(channel ssh3.Channel, remotePath string) bool {
	resp, err := doRequest(channel, &Request{Cmd: "stat", Path: remotePath})
	if err != nil || !resp.OK || resp.Info == nil {
		return false
	}
	return resp.Info.IsDir
}
