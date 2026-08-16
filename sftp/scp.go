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
func RunScpClient(c *client.Client, upload bool, recursive bool, localPath, remotePath string) error {
	channel, err := c.OpenChannel("sftp", 30000, 0)
	if err != nil {
		return fmt.Errorf("could not open sftp channel: %w", err)
	}
	defer channel.Close()
	if err := channel.WaitOpen(); err != nil {
		return fmt.Errorf("could not open sftp channel: %w", err)
	}

	if upload {
		return scpUpload(channel, recursive, localPath, remotePath)
	}
	return scpDownload(channel, recursive, remotePath, localPath)
}

// scpUpload copies a local file or directory to the remote host. Mirroring
// scp semantics, when the remote target is an existing directory or ends with
// a path separator, the source is copied into it under its own basename
// (e.g. `scp -r ./dir host:/tmp/` copies to /tmp/dir).
func scpUpload(channel ssh3.Channel, recursive bool, localPath, remotePath string) error {
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
		return uploadRecursive(channel, localPath, remotePath)
	}
	return uploadFile(channel, localPath, remotePath)
}

// scpDownload copies a remote file or directory to the local machine.
// Mirroring scp semantics, when the local target is an existing directory or
// ends with a path separator, the remote source is copied into it under its
// own basename (e.g. `scp -r host:/etc/nginx .` copies to ./nginx).
func scpDownload(channel ssh3.Channel, recursive bool, remotePath, localPath string) error {
	info, err := os.Stat(localPath)
	if err == nil && info.IsDir() {
		localPath = filepath.Join(localPath, filepath.Base(remotePath))
	} else if strings.HasSuffix(localPath, string(filepath.Separator)) {
		localPath = filepath.Join(localPath, filepath.Base(remotePath))
	}

	if recursive {
		return downloadRecursive(channel, remotePath, localPath)
	}
	return downloadFile(channel, remotePath, localPath)
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
