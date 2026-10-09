package sftp

import (
	"fmt"
	"os"
	"path"
	"strings"

	ssh3 "github.com/h4sh5/sshoq"
	"github.com/h4sh5/sshoq/client"
)

// RunRemoteCopyClient performs a single non-interactive copy between two remote
// hosts: -scp user@server1%file1 user@server2%file2. Neither server talks to
// the other one: the client keeps a connection (and an sftp channel) to each of
// them and streams the data through itself, like OpenSSH's "scp -3". Both sides
// therefore use the very same sftp request protocol as the local-to-remote and
// remote-to-local copies of -scp, and a host only ever serves its own
// filesystem with the privileges of the user authenticated on it.
//
// The source is srcPath on the src connection, the destination dstPath on the
// dst connection. A directory is only copied when recursive is set, and the
// scp destination rules apply: when dstPath names an existing directory on the
// destination host or ends with a "/", the source is copied into it under its
// own basename. "" and the "~"/"~/" forms of either path are resolved by their
// own server into the home directory of the user it has authenticated.
//
// SIGINT (Ctrl+C) and SIGTERM cancel the copy at the next chunk boundary and
// ErrCancelled is returned. Unlike a download to the local machine, the
// half-written file on the destination host is then left as it is: an
// interrupted copy has no business deleting files on a host it was only
// connected to in order to copy.
func RunRemoteCopyClient(src *client.Client, dst *client.Client, recursive bool, srcPath, dstPath string) error {
	srcChannel, err := openScpChannel(src)
	if err != nil {
		return err
	}
	defer srcChannel.Close()
	dstChannel, err := openScpChannel(dst)
	if err != nil {
		return err
	}
	defer dstChannel.Close()

	return runRemoteCopy(srcChannel, dstChannel, recursive, srcPath, dstPath)
}

// runRemoteCopy is the copy itself, once a channel has been opened on each of
// the two hosts: it resolves the home-directory forms of both paths, applies
// scp's destination rules and transfers, and cancels the copy when the user
// interrupts it.
func runRemoteCopy(src, dst ssh3.Channel, recursive bool, srcPath, dstPath string) error {
	// Each server resolves the home-directory forms ("" and "~") of its own
	// side, against the home of the user authenticated on it.
	srcPath, err := resolveScpRemotePath(src, srcPath)
	if err != nil {
		return err
	}
	dstPath, err = resolveScpRemotePath(dst, dstPath)
	if err != nil {
		return err
	}

	cancel := &transferCancel{}
	stop := watchSignals(cancel)
	defer stop()

	dstPath, err = scpRemoteDestination(src, dst, srcPath, dstPath)
	if err != nil {
		return err
	}
	return copyRemotePath(src, dst, srcPath, dstPath, recursive, cancel)
}

// scpRemoteDestination applies scp's "copy into the destination directory" rule
// to dstPath: when it names an existing directory on the destination host or
// ends with a path separator, the entry is copied into it under its own basename
// (the basename being the one of the source path, resolved on the source host).
// It is asked once, for the top-level entry: inside a recursive copy every
// child is copied to a destination name built from its own name.
func scpRemoteDestination(src, dst ssh3.Channel, srcPath, dstPath string) (string, error) {
	if !strings.HasSuffix(dstPath, "/") && !isRemoteDir(dst, dstPath) {
		return dstPath, nil
	}
	resp, err := doRequest(src, &Request{Cmd: "stat", Path: srcPath})
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", serverError(srcPath, resp.Error)
	}
	name := resp.Info.Name
	if name == "" || name == "." {
		// The source is the session's directory itself (a bare "...%~"): name
		// it after the directory the server reported.
		home, err := remoteHomeDir(src)
		if err != nil {
			return "", err
		}
		name = path.Base(home)
	}
	if name == "/" || name == "." || name == ".." {
		return "", fmt.Errorf("cannot copy %s into %s: cannot tell the name to give it on the destination host", srcPath, dstPath)
	}
	return path.Join(dstPath, name), nil
}

// copyRemotePath copies one entry, srcPath on the source host, to the exact
// destination name dstPath on the destination host. A symbolic link is resolved
// on the source host and copied as whatever it points at; a directory (or a
// symbolic link ending up on one) requires recursive.
func copyRemotePath(src, dst ssh3.Channel, srcPath, dstPath string, recursive bool, cancel *transferCancel) error {
	resolved, info, err := resolveRemote(src, srcPath, true)
	if err != nil {
		return err
	}
	if info == nil {
		return fmt.Errorf("cannot copy %s: the source host reported no information about it", srcPath)
	}
	if !info.IsDir {
		return copyRemoteFile(src, dst, resolved, dstPath, info.Size, cancel)
	}
	if !recursive {
		return fmt.Errorf("cannot copy directory %s: use -r for recursive copy", srcPath)
	}
	return copyRemoteDir(src, dst, resolved, dstPath, cancel)
}

// copyRemoteDir recreates the (already resolved) directory srcDir of the source
// host as dstPath on the destination host and copies every entry of it, walking
// subdirectories. A permission-denied entry is reported and skipped so the rest
// of the directory is still transferred.
func copyRemoteDir(src, dst ssh3.Channel, srcDir, dstPath string, cancel *transferCancel) error {
	if cancel.cancelled() {
		return ErrCancelled
	}
	if err := ensureRemoteDir(dst, dstPath); err != nil {
		return err
	}
	resp, err := doRequest(src, &Request{Cmd: "ls", Path: srcDir})
	if err != nil {
		return err
	}
	if !resp.OK {
		return serverError(srcDir, resp.Error)
	}
	for _, entry := range resp.Entries {
		childSrc := path.Join(srcDir, entry.Name)
		childDst := path.Join(dstPath, entry.Name)
		if entry.IsDir {
			if err := copyRemoteDir(src, dst, childSrc, childDst, cancel); err != nil {
				if isPermissionError(err) {
					fmt.Fprintf(os.Stderr, "copy: %s\n", err)
					continue
				}
				return err
			}
			continue
		}

		// A plain file or a symbolic link: the link is resolved on the source
		// host and its target copied under the link's name. A link pointing at a
		// directory is not walked into, because a link pointing back up the tree
		// would make the walk never end; it is reported and skipped.
		fileSrc, fileSize := childSrc, entry.Size
		if entry.IsSymlink {
			target, targetInfo, err := resolveRemote(src, childSrc, true)
			if err != nil {
				if isPermissionError(err) {
					fmt.Fprintf(os.Stderr, "copy: %s\n", err)
					continue
				}
				return err
			}
			if targetInfo != nil && targetInfo.IsDir {
				fmt.Fprintf(os.Stderr, "copy: %s: symbolic link to a directory, not followed\n", childSrc)
				continue
			}
			fileSrc, fileSize = target, 0
			if targetInfo != nil {
				fileSize = targetInfo.Size
			}
		}
		if err := copyRemoteFile(src, dst, fileSrc, childDst, fileSize, cancel); err != nil {
			if isPermissionError(err) {
				fmt.Fprintf(os.Stderr, "copy: %s\n", err)
				continue
			}
			return err
		}
	}
	return nil
}

// copyRemoteFile streams a single file from the source host to the destination
// host, total being the size the source announced (0 when unknown, in which
// case the progress line shows the transferred bytes without a percentage).
//
// Two windows are pipelined at once: reads are kept in flight on the source host
// exactly like a download does, and each chunk that arrives is written to the
// destination host, where writes are kept in flight like an upload does. The
// two links then run at their own speed and the slower one sets the pace: a new
// read is only issued when the destination's window has room for the chunk it
// would produce. In-flight memory stays bounded by 2×TransferWindow chunks.
//
// Both servers answer their requests strictly in order, so responses are
// consumed in request order and, on every error path, the responses still in
// flight are drained so the next file is not read through the errors of this
// one.
func copyRemoteFile(src, dst ssh3.Channel, srcPath, dstPath string, total int64, cancel *transferCancel) error {
	prog := newProgress(path.Base(srcPath), total, os.Stdout, cancel)
	done := false
	defer func() {
		if !done {
			prog.abort()
		}
	}()

	window := TransferWindow
	if total > 0 {
		if chunks := int((total + ChunkSize - 1) / ChunkSize); chunks < window {
			window = chunks
		}
	}
	if window < 1 {
		window = 1
	}

	// nextRead is the index of the chunk the next read request asks for; reads
	// stop once the server reports the end of the file, so a file that grows
	// while it is copied is still transferred in full.
	var nextRead int
	readsPending := 0
	fillReads := func() error {
		for readsPending < window {
			if cancel.cancelled() {
				return ErrCancelled
			}
			if err := SendRequest(src, &Request{Cmd: "get", Path: srcPath, Offset: int64(nextRead) * ChunkSize, Limit: ChunkSize}); err != nil {
				return err
			}
			nextRead++
			readsPending++
		}
		return nil
	}

	var nextWrite int64
	writesPending := 0
	// sendPut writes one chunk, waiting for the destination to acknowledge
	// enough of its in-flight writes for this one to fit in the window.
	sendPut := func(data []byte) error {
		for writesPending >= window {
			resp, err := ReceiveResponse(dst)
			if err != nil {
				return err
			}
			writesPending--
			if !resp.OK {
				return serverError(dstPath, resp.Error)
			}
		}
		if err := SendRequest(dst, &Request{Cmd: "put", Path: dstPath, Offset: nextWrite, Data: data}); err != nil {
			return err
		}
		nextWrite += int64(len(data))
		writesPending++
		return nil
	}

	drain := func() {
		for readsPending > 0 {
			readsPending--
			if _, err := ReceiveResponse(src); err != nil {
				break
			}
		}
		for writesPending > 0 {
			writesPending--
			if _, err := ReceiveResponse(dst); err != nil {
				break
			}
		}
	}

	var written int64
	created := false
	eof := false
	if err := fillReads(); err != nil {
		drain()
		return err
	}
	for readsPending > 0 || writesPending > 0 {
		if cancel.cancelled() {
			drain()
			return ErrCancelled
		}
		if readsPending > 0 {
			resp, err := ReceiveResponse(src)
			if err != nil {
				drain()
				return err
			}
			readsPending--
			if !resp.OK {
				err := serverError(srcPath, resp.Error)
				drain()
				return err
			}
			if len(resp.Data) == 0 {
				// End of file: stop refilling the window and consume the
				// responses already in flight (they are all empty as well).
				eof = true
				continue
			}
			if err := sendPut(resp.Data); err != nil {
				drain()
				return err
			}
			written += int64(len(resp.Data))
			created = true
			prog.add(int64(len(resp.Data)))
			if !eof {
				if err := fillReads(); err != nil {
					drain()
					return err
				}
			}
			continue
		}
		// The source is exhausted: only the destination's acknowledgements are
		// still outstanding.
		resp, err := ReceiveResponse(dst)
		if err != nil {
			drain()
			return err
		}
		writesPending--
		if !resp.OK {
			err := serverError(dstPath, resp.Error)
			drain()
			return err
		}
	}

	// An empty source still has to exist on the destination host: writing
	// nothing at offset 0 is what creates (and truncates) the file.
	if !created {
		if err := sendPut(nil); err != nil {
			drain()
			return err
		}
		for writesPending > 0 {
			resp, err := ReceiveResponse(dst)
			if err != nil {
				drain()
				return err
			}
			writesPending--
			if !resp.OK {
				err := serverError(dstPath, resp.Error)
				drain()
				return err
			}
		}
	}

	prog.finish()
	fmt.Printf("Copied %s to %s (%d bytes)\n", srcPath, dstPath, written)
	done = true
	return nil
}
