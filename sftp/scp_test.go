package sftp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScpUploadFileToTrailingSlashTarget verifies that an upload whose remote
// target ends with "/" copies the source into that directory under its own
// basename, like scp (scp file host:/tmp/ copies to /tmp/file).
func TestScpUploadFileToTrailingSlashTarget(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "local.txt")
	os.WriteFile(localPath, []byte("hello"), 0644)

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true}),
	)

	if err := scpUpload(ch, false, localPath, "/tmp/", nil); err != nil {
		t.Fatalf("scpUpload error: %v", err)
	}

	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	var got Request
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/tmp/local.txt" {
		t.Fatalf("expected put /tmp/local.txt, got %s %q", got.Cmd, got.Path)
	}
}

// TestScpUploadFileToExistingRemoteDir verifies that an upload whose remote
// target is an existing directory (without a trailing slash) copies the source
// into that directory under its own basename, like scp.
func TestScpUploadFileToExistingRemoteDir(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "local.txt")
	os.WriteFile(localPath, []byte("hello"), 0644)

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remotedir", IsDir: true}}),
		makeResponseMsg(&Response{ID: 2, OK: true}),
	)

	if err := scpUpload(ch, false, localPath, "/tmp/remotedir", nil); err != nil {
		t.Fatalf("scpUpload error: %v", err)
	}

	if len(ch.Writes) != 2 {
		t.Fatalf("expected 2 requests (stat + put), got %d", len(ch.Writes))
	}
	var statReq, putReq Request
	if err := decodeRequestFrame(ch.Writes[0], &statReq); err != nil {
		t.Fatalf("unmarshal stat: %v", err)
	}
	if err := decodeRequestFrame(ch.Writes[1], &putReq); err != nil {
		t.Fatalf("unmarshal put: %v", err)
	}
	if statReq.Cmd != "stat" || statReq.Path != "/tmp/remotedir" {
		t.Fatalf("expected stat /tmp/remotedir, got %s %q", statReq.Cmd, statReq.Path)
	}
	if putReq.Cmd != "put" || putReq.Path != "/tmp/remotedir/local.txt" {
		t.Fatalf("expected put /tmp/remotedir/local.txt, got %s %q", putReq.Cmd, putReq.Path)
	}
}

// TestScpUploadFileToNewRemoteName verifies that an upload whose remote target
// does not exist and has no trailing slash uses the target as the remote file
// name verbatim, like scp (scp file host:/tmp/newname copies to /tmp/newname).
func TestScpUploadFileToNewRemoteName(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "local.txt")
	os.WriteFile(localPath, []byte("hello"), 0644)

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: false, Error: "no such file"}),
		makeResponseMsg(&Response{ID: 2, OK: true}),
	)

	if err := scpUpload(ch, false, localPath, "/tmp/remotefile", nil); err != nil {
		t.Fatalf("scpUpload error: %v", err)
	}

	if len(ch.Writes) != 2 {
		t.Fatalf("expected 2 requests (stat + put), got %d", len(ch.Writes))
	}
	var putReq Request
	if err := decodeRequestFrame(ch.Writes[1], &putReq); err != nil {
		t.Fatalf("unmarshal put: %v", err)
	}
	if putReq.Cmd != "put" || putReq.Path != "/tmp/remotefile" {
		t.Fatalf("expected put /tmp/remotefile, got %s %q", putReq.Cmd, putReq.Path)
	}
}

// TestScpUploadDirectoryWithoutRecursive verifies that uploading a directory
// without -r fails with a clear error.
func TestScpUploadDirectoryWithoutRecursive(t *testing.T) {
	tmp := t.TempDir()
	localDir := filepath.Join(tmp, "adir")
	os.Mkdir(localDir, 0755)

	ch := newMockChannel()
	err := scpUpload(ch, false, localDir, "/tmp/", nil)
	if err == nil {
		t.Fatal("expected error for directory upload without -r")
	}
}

// TestScpUploadRecursiveDirectoryToTrailingSlashTarget verifies that a
// recursive directory upload to a target ending with "/" copies the directory
// into the target under its own basename, like scp -r (scp -r ./dir host:/tmp/
// copies to /tmp/dir).
func TestScpUploadRecursiveDirectoryToTrailingSlashTarget(t *testing.T) {
	tmp := t.TempDir()
	localDir := filepath.Join(tmp, "localfolder")
	os.MkdirAll(filepath.Join(localDir, "sub"), 0o755)
	os.WriteFile(filepath.Join(localDir, "a.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(localDir, "sub", "b.txt"), []byte("b"), 0644)

	// Requests performed by uploadRecursive for a directory tree with two
	// files:
	//   ensureRemoteDir("/tmp/localfolder"):
	//     stat("/tmp/localfolder") -> not found
	//     stat("/tmp") -> is a directory
	//     mkdir("/tmp/localfolder") -> ok
	//   upload file "a.txt":
	//     put("/tmp/localfolder/a.txt") -> ok
	//   ensureRemoteDir("/tmp/localfolder/sub"):
	//     stat("/tmp/localfolder/sub") -> not found
	//     stat("/tmp/localfolder") -> is a directory
	//     mkdir("/tmp/localfolder/sub") -> ok
	//   upload file "b.txt":
	//     put("/tmp/localfolder/sub/b.txt") -> ok
	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: false, Error: "no such file"}),
		makeResponseMsg(&Response{ID: 2, OK: true, Info: &FileInfo{Name: "tmp", IsDir: true}}),
		makeResponseMsg(&Response{ID: 3, OK: true}),
		makeResponseMsg(&Response{ID: 4, OK: true}),
		makeResponseMsg(&Response{ID: 5, OK: false, Error: "no such file"}),
		makeResponseMsg(&Response{ID: 6, OK: true, Info: &FileInfo{Name: "localfolder", IsDir: true}}),
		makeResponseMsg(&Response{ID: 7, OK: true}),
		makeResponseMsg(&Response{ID: 8, OK: true}),
	)

	if err := scpUpload(ch, true, localDir, "/tmp/", nil); err != nil {
		t.Fatalf("scpUpload -r error: %v", err)
	}

	if len(ch.Writes) != 8 {
		t.Fatalf("expected 8 requests, got %d", len(ch.Writes))
	}
	var mkdirReq Request
	if err := decodeRequestFrame(ch.Writes[2], &mkdirReq); err != nil {
		t.Fatalf("unmarshal mkdir: %v", err)
	}
	if mkdirReq.Cmd != "mkdir" || mkdirReq.Path != "/tmp/localfolder" {
		t.Fatalf("expected mkdir /tmp/localfolder, got %s %q", mkdirReq.Cmd, mkdirReq.Path)
	}
}

// TestScpDownloadToExistingLocalDir verifies that a download whose local
// target is an existing directory copies the remote source into it under its
// own basename, like scp (scp host:.ssh/authorized_keys . copies to
// ./authorized_keys).
func TestScpDownloadToExistingLocalDir(t *testing.T) {
	tmp := t.TempDir()
	content := []byte("hello from remote")

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote.txt", Size: int64(len(content))}}),
		makeResponseMsg(&Response{ID: 2, OK: true, Data: content}),
		makeResponseMsg(&Response{ID: 3, OK: true, Data: []byte{}}),
	)

	if err := scpDownload(ch, false, "/etc/remote.txt", tmp, nil); err != nil {
		t.Fatalf("scpDownload error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(tmp, "remote.txt"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("unexpected content: %q", got)
	}

	var statReq Request
	if len(ch.Writes) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(ch.Writes))
	}
	if err := decodeRequestFrame(ch.Writes[0], &statReq); err != nil {
		t.Fatalf("unmarshal stat: %v", err)
	}
	if statReq.Cmd != "stat" || statReq.Path != "/etc/remote.txt" {
		t.Fatalf("expected stat /etc/remote.txt, got %s %q", statReq.Cmd, statReq.Path)
	}
}

// TestScpDownloadToTrailingSlashLocalTarget verifies that a download whose
// local target ends with a path separator copies the remote source into that
// directory under its own basename.
func TestScpDownloadToTrailingSlashLocalTarget(t *testing.T) {
	tmp := t.TempDir()
	content := []byte("hello")

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote.txt", Size: int64(len(content))}}),
		makeResponseMsg(&Response{ID: 2, OK: true, Data: content}),
		makeResponseMsg(&Response{ID: 3, OK: true, Data: []byte{}}),
	)

	target := filepath.Join(tmp, "out") + string(filepath.Separator)
	if err := scpDownload(ch, false, "/etc/remote.txt", target, nil); err != nil {
		t.Fatalf("scpDownload error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(tmp, "out", "remote.txt"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("unexpected content: %q", got)
	}
}

// TestScpDownloadToNewLocalName verifies that a download whose local target
// does not exist and has no trailing separator uses the target as the local
// file name verbatim, like scp (scp host:file newname copies to ./newname).
func TestScpDownloadToNewLocalName(t *testing.T) {
	tmp := t.TempDir()
	content := []byte("hello")

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote.txt", Size: int64(len(content))}}),
		makeResponseMsg(&Response{ID: 2, OK: true, Data: content}),
		makeResponseMsg(&Response{ID: 3, OK: true, Data: []byte{}}),
	)

	newName := filepath.Join(tmp, "newname")
	if err := scpDownload(ch, false, "/etc/remote.txt", newName, nil); err != nil {
		t.Fatalf("scpDownload error: %v", err)
	}

	got, err := os.ReadFile(newName)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("unexpected content: %q", got)
	}
}

// TestScpDownloadRecursiveToExistingLocalDir verifies that a recursive
// directory download to an existing local directory copies the remote directory
// into it under its own basename, like scp -r (scp -r host:/etc/nginx . copies
// to ./nginx).
func TestScpDownloadRecursiveToExistingLocalDir(t *testing.T) {
	tmp := t.TempDir()

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "nginx", IsDir: true}}),
		makeResponseMsg(&Response{ID: 2, OK: true, Entries: []FileInfo{{Name: "nginx.conf", Size: 4, Mode: 0644}}}),
		makeResponseMsg(&Response{ID: 3, OK: true, Data: []byte("conf")}),
		makeResponseMsg(&Response{ID: 4, OK: true, Data: []byte{}}),
	)

	if err := scpDownload(ch, true, "/etc/nginx", tmp, nil); err != nil {
		t.Fatalf("scpDownload -r error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(tmp, "nginx", "nginx.conf"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != "conf" {
		t.Fatalf("unexpected content: %q", got)
	}
}

// TestScpUploadMissingLocalFile verifies that uploading a non-existent local
// path fails cleanly.
func TestScpUploadMissingLocalFile(t *testing.T) {
	ch := newMockChannel()
	err := scpUpload(ch, false, "/nonexistent/file.txt", "/tmp/", nil)
	if err == nil {
		t.Fatal("expected error for missing local file")
	}
}

// TestResolveScpRemotePathEmptyUsesHome verifies that an empty remote path
// (user@host:443/sshoq-server% with nothing after the separator) resolves to the
// remote user's home directory, which the server reports as the current
// directory of the SFTP session, like scp's "host:".
func TestResolveScpRemotePathEmptyUsesHome(t *testing.T) {
	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true, Path: "/home/alice"}),
	)

	got, err := resolveScpRemotePath(ch, "")
	if err != nil {
		t.Fatalf("resolveScpRemotePath error: %v", err)
	}
	if got != "/home/alice" {
		t.Fatalf("expected /home/alice, got %q", got)
	}
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request (pwd), got %d", len(ch.Writes))
	}
	var pwdReq Request
	if err := decodeRequestFrame(ch.Writes[0], &pwdReq); err != nil {
		t.Fatalf("decode pwd request: %v", err)
	}
	if pwdReq.Cmd != "pwd" {
		t.Fatalf("expected pwd request, got %q", pwdReq.Cmd)
	}
}

// TestResolveScpRemotePathTilde verifies that the tilde forms of the remote path
// resolve to the home directory reported by the server, like scp's "host:~" and
// "host:~/dir", and that a trailing separator is kept so the home directory
// itself is used as a directory target.
func TestResolveScpRemotePathTilde(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"~", "/home/alice"},
		{"~/", "/home/alice/"},
		{"~/sub", "/home/alice/sub"},
		{"~/sub/", "/home/alice/sub/"},
	} {
		ch := newMockChannel(
			makeResponseMsg(&Response{ID: 1, OK: true, Path: "/home/alice"}),
		)
		got, err := resolveScpRemotePath(ch, tc.in)
		if err != nil {
			t.Fatalf("resolveScpRemotePath(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("resolveScpRemotePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestResolveScpRemotePathLeavesOtherPathsAlone verifies that an explicit remote
// path needs no request at all: absolute paths stay absolute and relative ones
// keep resolving against the session directory on the server.
func TestResolveScpRemotePathLeavesOtherPathsAlone(t *testing.T) {
	for _, in := range []string{"/tmp/remotefile", ".ssh/authorized_keys", "x", "/~user/x"} {
		ch := newMockChannel()
		got, err := resolveScpRemotePath(ch, in)
		if err != nil {
			t.Fatalf("resolveScpRemotePath(%q) error: %v", in, err)
		}
		if got != in {
			t.Errorf("resolveScpRemotePath(%q) = %q, want it unchanged", in, got)
		}
		if len(ch.Writes) != 0 {
			t.Errorf("resolveScpRemotePath(%q) issued %d requests, want none", in, len(ch.Writes))
		}
	}
}

// TestResolveScpRemotePathHomeLookupFailure verifies that a server refusing to
// report its current directory is reported as an error naming the home
// directory rather than silently copying to an empty path.
func TestResolveScpRemotePathHomeLookupFailure(t *testing.T) {
	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: false, Error: "permission denied"}),
	)
	_, err := resolveScpRemotePath(ch, "")
	if err == nil {
		t.Fatal("expected error when the server does not report its directory")
	}
	if !strings.Contains(err.Error(), "home directory") {
		t.Errorf("expected the error to mention the home directory, got %v", err)
	}
}

// TestScpUploadWithoutRemotePathGoesToHome verifies a whole upload with no remote
// path: the home directory reported by the server is the destination directory,
// so the source lands in it under its own basename
// (sshoq -scp ./file.txt user@host:443/sshoq-server% copies to ~/file.txt).
func TestScpUploadWithoutRemotePathGoesToHome(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "local.txt")
	if err := os.WriteFile(localPath, []byte("hello home"), 0644); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true, Path: "/home/alice"}),
		makeResponseMsg(&Response{ID: 2, OK: true, Info: &FileInfo{Name: "alice", IsDir: true}}),
		makeResponseMsg(&Response{ID: 3, OK: true}),
	)

	remotePath, err := resolveScpRemotePath(ch, "")
	if err != nil {
		t.Fatalf("resolveScpRemotePath error: %v", err)
	}
	if err := scpUpload(ch, false, localPath, remotePath, nil); err != nil {
		t.Fatalf("scpUpload error: %v", err)
	}

	if len(ch.Writes) != 3 {
		t.Fatalf("expected 3 requests (pwd, stat, put), got %d", len(ch.Writes))
	}
	var putReq Request
	if err := decodeRequestFrame(ch.Writes[2], &putReq); err != nil {
		t.Fatalf("decode put request: %v", err)
	}
	if putReq.Cmd != "put" || putReq.Path != "/home/alice/local.txt" {
		t.Fatalf("expected put /home/alice/local.txt, got %s %q", putReq.Cmd, putReq.Path)
	}
}
