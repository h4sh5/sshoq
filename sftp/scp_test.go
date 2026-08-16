package sftp

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		makeJSONDataMsg(&Response{ID: 1, OK: true}),
	)

	if err := scpUpload(ch, false, localPath, "/tmp/"); err != nil {
		t.Fatalf("scpUpload error: %v", err)
	}

	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	var got Request
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
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
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remotedir", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true}),
	)

	if err := scpUpload(ch, false, localPath, "/tmp/remotedir"); err != nil {
		t.Fatalf("scpUpload error: %v", err)
	}

	if len(ch.Writes) != 2 {
		t.Fatalf("expected 2 requests (stat + put), got %d", len(ch.Writes))
	}
	var statReq, putReq Request
	if err := json.Unmarshal(ch.Writes[0], &statReq); err != nil {
		t.Fatalf("unmarshal stat: %v", err)
	}
	if err := json.Unmarshal(ch.Writes[1], &putReq); err != nil {
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
		makeJSONDataMsg(&Response{ID: 1, OK: false, Error: "no such file"}),
		makeJSONDataMsg(&Response{ID: 2, OK: true}),
	)

	if err := scpUpload(ch, false, localPath, "/tmp/remotefile"); err != nil {
		t.Fatalf("scpUpload error: %v", err)
	}

	if len(ch.Writes) != 2 {
		t.Fatalf("expected 2 requests (stat + put), got %d", len(ch.Writes))
	}
	var putReq Request
	if err := json.Unmarshal(ch.Writes[1], &putReq); err != nil {
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
	err := scpUpload(ch, false, localDir, "/tmp/")
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
		makeJSONDataMsg(&Response{ID: 1, OK: false, Error: "no such file"}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Info: &FileInfo{Name: "tmp", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 3, OK: true}),
		makeJSONDataMsg(&Response{ID: 4, OK: true}),
		makeJSONDataMsg(&Response{ID: 5, OK: false, Error: "no such file"}),
		makeJSONDataMsg(&Response{ID: 6, OK: true, Info: &FileInfo{Name: "localfolder", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 7, OK: true}),
		makeJSONDataMsg(&Response{ID: 8, OK: true}),
	)

	if err := scpUpload(ch, true, localDir, "/tmp/"); err != nil {
		t.Fatalf("scpUpload -r error: %v", err)
	}

	if len(ch.Writes) != 8 {
		t.Fatalf("expected 8 requests, got %d", len(ch.Writes))
	}
	var mkdirReq Request
	if err := json.Unmarshal(ch.Writes[2], &mkdirReq); err != nil {
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
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote.txt", Size: int64(len(content))}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Data: content}),
		makeJSONDataMsg(&Response{ID: 3, OK: true, Data: []byte{}}),
	)

	if err := scpDownload(ch, false, "/etc/remote.txt", tmp); err != nil {
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
	if err := json.Unmarshal(ch.Writes[0], &statReq); err != nil {
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
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote.txt", Size: int64(len(content))}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Data: content}),
		makeJSONDataMsg(&Response{ID: 3, OK: true, Data: []byte{}}),
	)

	target := filepath.Join(tmp, "out") + string(filepath.Separator)
	if err := scpDownload(ch, false, "/etc/remote.txt", target); err != nil {
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
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote.txt", Size: int64(len(content))}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Data: content}),
		makeJSONDataMsg(&Response{ID: 3, OK: true, Data: []byte{}}),
	)

	newName := filepath.Join(tmp, "newname")
	if err := scpDownload(ch, false, "/etc/remote.txt", newName); err != nil {
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
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "nginx", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Entries: []FileInfo{{Name: "nginx.conf", Size: 4, Mode: 0644}}}),
		makeJSONDataMsg(&Response{ID: 3, OK: true, Data: []byte("conf")}),
		makeJSONDataMsg(&Response{ID: 4, OK: true, Data: []byte{}}),
	)

	if err := scpDownload(ch, true, "/etc/nginx", tmp); err != nil {
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
	err := scpUpload(ch, false, "/nonexistent/file.txt", "/tmp/")
	if err == nil {
		t.Fatal("expected error for missing local file")
	}
}
