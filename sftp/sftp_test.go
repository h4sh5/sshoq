package sftp

import (
	"encoding/json"
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
	"github.com/h4sh5/sshoq/util/unix_util"
)

func currentTestUser(dir string) *unix_util.User {
	username := ""
	if u, err := osuser.Current(); err == nil {
		username = u.Username
	}
	return &unix_util.User{
		Username: username,
		Uid:      uint64(os.Getuid()),
		Gid:      uint64(os.Getgid()),
		Dir:      dir,
	}
}

func makeDataMsg(data []byte) *ssh3Messages.DataOrExtendedDataMessage {
	return &ssh3Messages.DataOrExtendedDataMessage{
		DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE,
		Data:     string(data),
	}
}

func makeJSONDataMsg(v interface{}) *ssh3Messages.DataOrExtendedDataMessage {
	b, _ := json.Marshal(v)
	return makeDataMsg(b)
}

// newMockChannel creates a ssh3.MockChannel wired with pre-programmed messages.
func newMockChannel(msgs ...ssh3Messages.Message) *ssh3.MockChannel {
	return ssh3.NewMockChannel(msgs...)
}

// --- Protocol tests ---

func TestSendRequest(t *testing.T) {
	ch := newMockChannel()
	req := &Request{ID: 1, Cmd: "pwd"}
	if err := SendRequest(ch, req); err != nil {
		t.Fatalf("SendRequest error: %v", err)
	}
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(ch.Writes))
	}
	var got Request
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if got.Cmd != "pwd" || got.ID != 1 {
		t.Fatalf("unexpected request: %+v", got)
	}
}

func TestReceiveResponse(t *testing.T) {
	want := &Response{ID: 2, OK: true, Path: "/tmp"}
	ch := newMockChannel(makeJSONDataMsg(want))
	got, err := ReceiveResponse(ch)
	if err != nil {
		t.Fatalf("ReceiveResponse error: %v", err)
	}
	if got.ID != want.ID || got.OK != want.OK || got.Path != want.Path {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestReceiveResponse_WrongMessageType(t *testing.T) {
	ch := newMockChannel(&ssh3Messages.ChannelRequestMessage{})
	_, err := ReceiveResponse(ch)
	if err == nil {
		t.Fatal("expected error for non-data message")
	}
}

// --- Server tests ---

func TestServerHandleRequest_pwd(t *testing.T) {
	sess := &ServerSession{currentDir: "/home/user"}
	resp := sess.handleRequest(Request{Cmd: "pwd"})
	if !resp.OK || resp.Path != "/home/user" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestServerHandleRequest_cd(t *testing.T) {
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "subdir")
	os.Mkdir(sub, 0755)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "cd", Path: "subdir"})
	if !resp.OK {
		t.Fatalf("cd failed: %s", resp.Error)
	}
	if sess.currentDir != sub {
		t.Fatalf("expected currentDir %s, got %s", sub, sess.currentDir)
	}
}

func TestServerHandleRequest_cdNotDir(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "file.txt")
	os.WriteFile(f, []byte("x"), 0644)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "cd", Path: "file.txt"})
	if resp.OK || resp.Error != "not a directory" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestServerHandleRequest_ls(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("a"), 0644)
	os.Mkdir(filepath.Join(tmp, "b_dir"), 0755)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "ls", Path: "."})
	if !resp.OK {
		t.Fatalf("ls failed: %s", resp.Error)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(resp.Entries))
	}
}

func TestServerHandleRequest_stat(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.txt")
	os.WriteFile(f, []byte("hello"), 0644)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "stat", Path: "test.txt"})
	if !resp.OK {
		t.Fatalf("stat failed: %s", resp.Error)
	}
	if resp.Info == nil || resp.Info.Name != "test.txt" || resp.Info.Size != 5 {
		t.Fatalf("unexpected info: %+v", resp.Info)
	}
}

func TestServerHandleRequest_get(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "data.bin")
	want := []byte("hello world")
	os.WriteFile(f, want, 0644)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "get", Path: "data.bin", Limit: 5})
	if !resp.OK {
		t.Fatalf("get failed: %s", resp.Error)
	}
	if string(resp.Data) != "hello" {
		t.Fatalf("unexpected data: %q", resp.Data)
	}

	resp2 := sess.handleRequest(Request{Cmd: "get", Path: "data.bin", Offset: 5, Limit: 10})
	if !resp2.OK {
		t.Fatalf("get offset failed: %s", resp2.Error)
	}
	if string(resp2.Data) != " world" {
		t.Fatalf("unexpected offset data: %q", resp2.Data)
	}
}

func TestServerHandleRequest_getOffsetEOF(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "small.txt")
	os.WriteFile(f, []byte("ab"), 0644)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "get", Path: "small.txt", Offset: 2, Limit: 10})
	if !resp.OK {
		t.Fatalf("get failed: %s", resp.Error)
	}
	if len(resp.Data) != 0 {
		t.Fatalf("expected empty data at EOF, got %q", resp.Data)
	}
}

func TestServerHandleRequest_put(t *testing.T) {
	tmp := t.TempDir()
	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "put", Path: "out.txt", Data: []byte("chunk1")})
	if !resp.OK {
		t.Fatalf("put failed: %s", resp.Error)
	}

	resp2 := sess.handleRequest(Request{Cmd: "put", Path: "out.txt", Offset: 6, Data: []byte("chunk2")})
	if !resp2.OK {
		t.Fatalf("put offset failed: %s", resp2.Error)
	}

	got, err := os.ReadFile(filepath.Join(tmp, "out.txt"))
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(got) != "chunk1chunk2" {
		t.Fatalf("unexpected file content: %q", got)
	}
}

func TestServerHandleRequest_putDoesNotCreateParentDir(t *testing.T) {
	tmp := t.TempDir()
	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "put", Path: filepath.Join("nested", "file.txt"), Data: []byte("x")})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected put failure without parent directory, got %+v", resp)
	}
	_, err := os.Stat(filepath.Join(tmp, "nested", "file.txt"))
	if !os.IsNotExist(err) {
		t.Fatalf("file should not exist, got err=%v", err)
	}
}

func TestServerHandleRequest_mkdir(t *testing.T) {
	tmp := t.TempDir()
	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "mkdir", Path: "newdir"})
	if !resp.OK {
		t.Fatalf("mkdir failed: %s", resp.Error)
	}
	info, err := os.Stat(filepath.Join(tmp, "newdir"))
	if err != nil || !info.IsDir() {
		t.Fatalf("directory not created")
	}
}

func TestServerHandleRequest_rm(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "del.txt")
	os.WriteFile(f, []byte("x"), 0644)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "rm", Path: "del.txt"})
	if !resp.OK {
		t.Fatalf("rm failed: %s", resp.Error)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("file should not exist after rm")
	}
}

func TestServerHandleRequest_rmdir(t *testing.T) {
	tmp := t.TempDir()
	d := filepath.Join(tmp, "deldir")
	os.Mkdir(d, 0755)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "rmdir", Path: "deldir"})
	if !resp.OK {
		t.Fatalf("rmdir failed: %s", resp.Error)
	}
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Fatal("directory should not exist after rmdir")
	}
}

func TestServerHandleRequest_rmdirNonEmptyFails(t *testing.T) {
	tmp := t.TempDir()
	d := filepath.Join(tmp, "deldir")
	os.Mkdir(d, 0755)
	os.WriteFile(filepath.Join(d, "inner.txt"), []byte("x"), 0644)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "rmdir", Path: "deldir"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected rmdir failure for non-empty directory, got %+v", resp)
	}
}

func TestServerHandleRequest_unknown(t *testing.T) {
	sess := &ServerSession{currentDir: "/"}
	resp := sess.handleRequest(Request{Cmd: "xyzzy"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("unexpected response for unknown cmd: %+v", resp)
	}
}

func TestServerResolvePath(t *testing.T) {
	sess := &ServerSession{currentDir: "/home/user"}
	cases := []struct {
		in, want string
	}{
		{"foo", "/home/user/foo"},
		{"/abs", "/abs"},
		{"", "/home/user"},
	}
	for _, c := range cases {
		got := sess.resolvePath(c.in)
		if got != c.want {
			t.Errorf("resolvePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestServerRespond(t *testing.T) {
	ch := newMockChannel()
	sess := &ServerSession{channel: ch}
	resp := &Response{ID: 42, OK: true}
	if err := sess.respond(resp); err != nil {
		t.Fatalf("respond error: %v", err)
	}
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(ch.Writes))
	}
	var got Response
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if got.ID != 42 || !got.OK {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestServeChannel_EOF(t *testing.T) {
	ch := newMockChannel() // no messages => EOF immediately
	user := currentTestUser(t.TempDir())
	ServeChannel(nil, user, ch)
	if !ch.Closed {
		t.Fatal("expected channel to be closed on EOF")
	}
}

// --- Client tests ---

func TestSftpFileInfoFromEntry(t *testing.T) {
	e := FileInfo{Name: "foo", Size: 42, Mode: 0644, IsDir: false, ModTime: 1234567890}
	info := sftpFileInfoFromEntry(e)
	if info.Name() != "foo" || info.Size() != 42 || info.IsDir() || info.Mode() != 0644 {
		t.Fatalf("unexpected FileInfo: %+v", info)
	}
}

func TestDownloadFile(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "downloaded.txt")
	remoteContent := []byte("hello from remote")

	statResp := &Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote.txt", Size: int64(len(remoteContent))}}
	chunk1 := &Response{ID: 2, OK: true, Data: remoteContent[:5]}
	chunk2 := &Response{ID: 3, OK: true, Data: remoteContent[5:]}
	done := &Response{ID: 4, OK: true, Data: []byte{}}

	ch := newMockChannel(
		makeJSONDataMsg(statResp),
		makeJSONDataMsg(chunk1),
		makeJSONDataMsg(chunk2),
		makeJSONDataMsg(done),
	)

	if err := downloadFile(ch, "remote.txt", localPath); err != nil {
		t.Fatalf("downloadFile error: %v", err)
	}
	got, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(got) != string(remoteContent) {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestDownloadFile_StatFail(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{ID: 1, OK: false, Error: "no such file"}))
	err := downloadFile(ch, "missing", filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Fatal("expected error for stat failure")
	}
}

func TestUploadFile(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "local.txt")
	content := []byte("upload me")
	os.WriteFile(localPath, content, 0644)

	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: true}),
	)

	// Verify that uploadFile sends the data through the channel without error.
	// The remote side would write the file; our mock just acknowledges.
	if err := uploadFile(ch, localPath, "remote.txt"); err != nil {
		t.Fatalf("uploadFile error: %v", err)
	}
	// One chunk was sent because the content is smaller than ChunkSize.
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 written request, got %d", len(ch.Writes))
	}
}

func TestDownloadRecursive(t *testing.T) {
	tmp := t.TempDir()
	localRoot := filepath.Join(tmp, "downloaded")

	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote-dir", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Entries: []FileInfo{{Name: "subdir", IsDir: true}, {Name: "file.txt", Size: 5, Mode: 0644}}}),
		makeJSONDataMsg(&Response{ID: 3, OK: true, Info: &FileInfo{Name: "subdir", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 4, OK: true, Entries: []FileInfo{{Name: "nested.txt", Size: 11, Mode: 0644}}}),
		makeJSONDataMsg(&Response{ID: 5, OK: true, Data: []byte("hello world")}),
		makeJSONDataMsg(&Response{ID: 6, OK: true, Data: []byte{}}),
		makeJSONDataMsg(&Response{ID: 7, OK: true, Data: []byte("hello")}),
		makeJSONDataMsg(&Response{ID: 8, OK: true, Data: []byte{}}),
	)

	if err := downloadRecursive(ch, "remote-dir", localRoot); err != nil {
		t.Fatalf("downloadRecursive error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(localRoot, "file.txt"))
	if err != nil {
		t.Fatalf("read root file: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("unexpected root file content: %q", got)
	}

	nested, err := os.ReadFile(filepath.Join(localRoot, "subdir", "nested.txt"))
	if err != nil {
		t.Fatalf("read nested file: %v", err)
	}
	if string(nested) != "hello world" {
		t.Fatalf("unexpected nested file content: %q", nested)
	}
}

func TestUploadRecursive(t *testing.T) {
	tmp := t.TempDir()
	localRoot := filepath.Join(tmp, "local-dir")
	os.MkdirAll(filepath.Join(localRoot, "subdir"), 0o755)
	os.WriteFile(filepath.Join(localRoot, "file.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(localRoot, "subdir", "nested.txt"), []byte("world"), 0644)

	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: false, Error: "no such file"}),
		makeJSONDataMsg(&Response{ID: 2, OK: true}),
		makeJSONDataMsg(&Response{ID: 3, OK: true}),
		makeJSONDataMsg(&Response{ID: 4, OK: true, Info: &FileInfo{Name: "subdir", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 5, OK: true}),
	)

	if err := uploadRecursive(ch, localRoot, "remote-dir"); err != nil {
		t.Fatalf("uploadRecursive error: %v", err)
	}
	if len(ch.Writes) != 5 {
		t.Fatalf("expected 5 requests, got %d", len(ch.Writes))
	}
}

func TestUploadFile_DirectoryError(t *testing.T) {
	tmp := t.TempDir()
	dirPath := filepath.Join(tmp, "adir")
	os.Mkdir(dirPath, 0755)

	ch := newMockChannel()
	err := uploadFile(ch, dirPath, "/remote/file")
	if err == nil || err.Error() != "cannot upload a directory" {
		t.Fatalf("expected directory upload error, got: %v", err)
	}
}

func TestDoRequest(t *testing.T) {
	want := &Response{ID: 7, OK: true, Path: "/tmp"}
	ch := newMockChannel(makeJSONDataMsg(want))
	got, err := doRequest(ch, &Request{Cmd: "pwd"})
	if err != nil {
		t.Fatalf("doRequest error: %v", err)
	}
	if !got.OK || got.Path != "/tmp" {
		t.Fatalf("unexpected response: %+v", got)
	}

	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 written request, got %d", len(ch.Writes))
	}
	var req Request
	if err := json.Unmarshal(ch.Writes[0], &req); err != nil {
		t.Fatalf("unmarshal written request: %v", err)
	}
	if req.Cmd != "pwd" {
		t.Fatalf("unexpected written request: %+v", req)
	}
}

// --- Chunked transfer size boundary tests ---

func TestChunkSizeConstant(t *testing.T) {
	if ChunkSize != 16*1024 {
		t.Fatalf("ChunkSize expected %d, got %d", 16*1024, ChunkSize)
	}
}

func TestServerHandleRequest_getLargeFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "large.bin")
	data := make([]byte, ChunkSize+100)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(f, data, 0644)

	sess := &ServerSession{currentDir: tmp}
	resp1 := sess.handleRequest(Request{Cmd: "get", Path: "large.bin", Offset: 0, Limit: ChunkSize})
	if !resp1.OK {
		t.Fatalf("first get failed: %s", resp1.Error)
	}
	if len(resp1.Data) != ChunkSize {
		t.Fatalf("expected first chunk %d bytes, got %d", ChunkSize, len(resp1.Data))
	}

	resp2 := sess.handleRequest(Request{Cmd: "get", Path: "large.bin", Offset: int64(ChunkSize), Limit: ChunkSize})
	if !resp2.OK {
		t.Fatalf("second get failed: %s", resp2.Error)
	}
	if len(resp2.Data) != 100 {
		t.Fatalf("expected second chunk 100 bytes, got %d", len(resp2.Data))
	}

	combined := append(resp1.Data, resp2.Data...)
	if string(combined) != string(data) {
		t.Fatal("reconstructed data does not match original")
	}
}

func TestServerHandleRequest_putLargeFile(t *testing.T) {
	tmp := t.TempDir()
	sess := &ServerSession{currentDir: tmp}
	data := make([]byte, ChunkSize+50)
	for i := range data {
		data[i] = byte((i + 1) % 256)
	}

	resp1 := sess.handleRequest(Request{Cmd: "put", Path: "large.bin", Offset: 0, Data: data[:ChunkSize]})
	if !resp1.OK {
		t.Fatalf("first put failed: %s", resp1.Error)
	}
	resp2 := sess.handleRequest(Request{Cmd: "put", Path: "large.bin", Offset: int64(ChunkSize), Data: data[ChunkSize:]})
	if !resp2.OK {
		t.Fatalf("second put failed: %s", resp2.Error)
	}

	got, err := os.ReadFile(filepath.Join(tmp, "large.bin"))
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(got) != string(data) {
		t.Fatal("reconstructed file does not match original")
	}
}

// --- Error handling tests ---

func TestServerHandleRequest_statMissing(t *testing.T) {
	tmp := t.TempDir()
	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "stat", Path: "missing"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected error for missing file, got %+v", resp)
	}
}

func TestServerHandleRequest_getMissing(t *testing.T) {
	tmp := t.TempDir()
	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "get", Path: "missing"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected error for missing file, got %+v", resp)
	}
}

func TestServerHandleRequest_getDeniedByPermissions(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "secret.txt")
	os.WriteFile(f, []byte("secret"), 0600)
	if err := os.Chmod(f, 0000); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	defer os.Chmod(f, 0600)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "get", Path: "secret.txt"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected permission error, got %+v", resp)
	}
}

func TestServerHandleRequest_putDeniedWhenParentNotWritable(t *testing.T) {
	tmp := t.TempDir()
	noWriteDir := filepath.Join(tmp, "readonly")
	if err := os.Mkdir(noWriteDir, 0555); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	defer os.Chmod(noWriteDir, 0755)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "put", Path: filepath.Join("readonly", "file.txt"), Data: []byte("x")})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected permission error, got %+v", resp)
	}
}

func TestServerHandleRequest_rmMissing(t *testing.T) {
	tmp := t.TempDir()
	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "rm", Path: "missing"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected error for missing file, got %+v", resp)
	}
}

func TestServerHandleRequest_lsMissing(t *testing.T) {
	tmp := t.TempDir()
	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "ls", Path: "missing"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected error for missing dir, got %+v", resp)
	}
}

// --- Integration-style end-to-end test for server handling two requests ---

func TestServeChannel_TwoRequests(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("alpha"), 0644)

	req1 := Request{Cmd: "pwd"}
	req2 := Request{Cmd: "ls", Path: "."}
	b1, _ := json.Marshal(req1)
	b2, _ := json.Marshal(req2)

	ch := newMockChannel(
		makeDataMsg(b1),
		makeDataMsg(b2),
	)

	user := currentTestUser(tmp)
	ServeChannel(nil, user, ch)

	if len(ch.Writes) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(ch.Writes))
	}
	var resp1 Response
	var resp2 Response
	json.Unmarshal(ch.Writes[0], &resp1)
	json.Unmarshal(ch.Writes[1], &resp2)

	if !resp1.OK || resp1.Path != tmp {
		t.Fatalf("unexpected resp1: %+v", resp1)
	}
	if !resp2.OK || len(resp2.Entries) != 1 {
		t.Fatalf("unexpected resp2: %+v", resp2)
	}
	if !ch.Closed {
		t.Fatal("expected channel closed")
	}
}

func TestDropPrivileges_NoOpWhenAlreadyTargetUser(t *testing.T) {
	u := currentTestUser(t.TempDir())
	if err := dropPrivileges(u); err != nil {
		t.Fatalf("dropPrivileges failed when already target user: %v", err)
	}
}

func TestDropPrivileges_RequiresUser(t *testing.T) {
	if err := dropPrivileges(nil); err == nil {
		t.Fatal("expected error for nil user")
	}
}

func TestBuildGroupIDs(t *testing.T) {
	u := currentTestUser(t.TempDir())
	gids, err := buildGroupIDs(u)
	if err != nil {
		t.Fatalf("buildGroupIDs error: %v", err)
	}
	if len(gids) == 0 {
		t.Fatal("expected at least one group")
	}
	foundPrimary := false
	for _, gid := range gids {
		if gid == int(u.Gid) {
			foundPrimary = true
			break
		}
	}
	if !foundPrimary {
		t.Fatalf("expected primary gid %d in %v", u.Gid, gids)
	}
}
