package sftp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
	"github.com/h4sh5/sshoq/util/unix_util"
)

// windowedMockChannel is a mock channel that delays every response until at
// least minWrites requests have been written to it. A client that transfers
// synchronously (send one request, wait for its response, send the next)
// would deadlock waiting for the first response before it can send the second
// request; the pipelined transfer loops send their whole initial window up
// front, so the pre-programmed responses are only served once the window is
// full. This pins the pipelining behaviour that keeps the pipe to the server
// full.
type windowedMockChannel struct {
	*ssh3.MockChannel
	mu        sync.Mutex
	cond      *sync.Cond
	minWrites int
	writes    int
}

func newWindowedMockChannel(minWrites int, msgs ...ssh3Messages.Message) *windowedMockChannel {
	c := &windowedMockChannel{
		MockChannel: ssh3.NewMockChannel(msgs...),
		minWrites:   minWrites,
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *windowedMockChannel) WriteData(dataBuf []byte, dataType ssh3Messages.SSHDataType) (int, error) {
	c.mu.Lock()
	c.writes++
	c.cond.Broadcast()
	c.mu.Unlock()
	return c.MockChannel.WriteData(dataBuf, dataType)
}

func (c *windowedMockChannel) NextMessage() (ssh3Messages.Message, error) {
	c.mu.Lock()
	for c.writes < c.minWrites {
		c.cond.Wait()
	}
	c.mu.Unlock()
	return c.MockChannel.NextMessage()
}

// runWithTimeout runs fn and fails the test if it does not return within the
// deadline, so a regression to a synchronous transfer (which would deadlock
// against a windowedMockChannel) fails promptly instead of hanging the suite.
func runWithTimeout(t *testing.T, what string, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not complete: the transfer is not pipelining", what)
		return nil
	}
}

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

func makeResponseMsg(resp *Response) *ssh3Messages.DataOrExtendedDataMessage {
	return makeDataMsg(EncodeResponse(resp))
}

// decodeRequestFrame and decodeResponseFrame decode a full frame as written
// to the channel (4-byte length prefix followed by the payload) into a
// Request/Response, mirroring the wire format.
func decodeRequestFrame(data []byte, req *Request) error {
	if len(data) < 4 {
		return errors.New("short request frame")
	}
	return DecodeRequest(data[4:], req)
}

func decodeResponseFrame(data []byte, resp *Response) error {
	if len(data) < 4 {
		return errors.New("short response frame")
	}
	return DecodeResponse(data[4:], resp)
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
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if got.Cmd != "pwd" || got.ID != 1 {
		t.Fatalf("unexpected request: %+v", got)
	}
}

func TestReceiveResponse(t *testing.T) {
	want := &Response{ID: 2, OK: true, Path: "/tmp"}
	ch := newMockChannel(makeResponseMsg(want))
	got, err := ReceiveResponse(ch)
	if err != nil {
		t.Fatalf("ReceiveResponse error: %v", err)
	}
	if got.ID != want.ID || got.OK != want.OK || got.Path != want.Path {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestReceiveResponse_SkipsNonDataMessages(t *testing.T) {
	want := &Response{ID: 2, OK: true, Path: "/tmp"}
	ch := newMockChannel(
		&ssh3Messages.ChannelRequestMessage{},
		makeResponseMsg(want),
	)
	got, err := ReceiveResponse(ch)
	if err != nil {
		t.Fatalf("ReceiveResponse error: %v", err)
	}
	if got.ID != want.ID || got.OK != want.OK || got.Path != want.Path {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestReceiveResponse_ChunkedMessage(t *testing.T) {
	// Build a large response that channelImpl.WriteData would split into
	// several channel data messages (each message carries at most
	// MaxPacketSize minus framing bytes). ReceiveResponse must reassemble the
	// chunks into a single JSON document instead of parsing a truncated one.
	var entries []FileInfo
	for i := 0; i < 800; i++ {
		entries = append(entries, FileInfo{
			Name:      fmt.Sprintf("file_%03d.txt", i),
			Size:      4096,
			Mode:      0644,
			IsDir:     false,
			ModTime:   1786842766,
			UID:       1000,
			GID:       1000,
			UserName:  "alice",
			GroupName: "alice",
		})
	}
	want := &Response{ID: 7, OK: true, Entries: entries}
	raw := EncodeResponse(want)

	msgs := splitIntoChannelMessages(raw)
	if len(msgs) < 2 {
		t.Fatalf("test response too small to be split across messages")
	}

	got, err := ReceiveResponse(newMockChannel(msgs...))
	if err != nil {
		t.Fatalf("ReceiveResponse error: %v", err)
	}
	if got.ID != want.ID || !got.OK || len(got.Entries) != len(want.Entries) {
		t.Fatalf("unexpected reassembled response: id=%d ok=%v entries=%d", got.ID, got.OK, len(got.Entries))
	}
	if got.Entries[0].Name != want.Entries[0].Name ||
		got.Entries[len(got.Entries)-1].Name != want.Entries[len(want.Entries)-1].Name {
		t.Fatalf("reassembled entries mismatch: first=%q last=%q",
			got.Entries[0].Name, got.Entries[len(got.Entries)-1].Name)
	}
}

// splitIntoChannelMessages splits raw into as many DataOrExtendedDataMessage
// payloads as channelImpl.WriteData would produce for a channel opened with the
// default maximum packet size of 30000 bytes.
func splitIntoChannelMessages(raw []byte) []ssh3Messages.Message {
	const maxPacketSize = 30000
	emptyMsgLen := (&ssh3Messages.DataOrExtendedDataMessage{
		DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE,
	}).Length()
	chunkSize := maxPacketSize - emptyMsgLen

	var msgs []ssh3Messages.Message
	for len(raw) > 0 {
		n := chunkSize
		if len(raw) < n {
			n = len(raw)
		}
		msgs = append(msgs, makeDataMsg(raw[:n]))
		raw = raw[n:]
	}
	return msgs
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
	if resp.OK || !strings.Contains(resp.Error, "not a directory") {
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

	// Ownership details must be populated for every entry.
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	for _, e := range resp.Entries {
		if e.UID != uid || e.GID != gid {
			t.Fatalf("expected entry %s owned by %d:%d, got %d:%d", e.Name, uid, gid, e.UID, e.GID)
		}
		if e.UserName == "" || e.GroupName == "" {
			t.Fatalf("expected user/group names on entry %s, got %+v", e.Name, e)
		}
	}
}

func TestServerHandleRequest_lsOwnershipNames(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "f.txt"), []byte("x"), 0644)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "ls", Path: "."})
	if !resp.OK || len(resp.Entries) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}

	e := resp.Entries[0]
	uidName := strconv.FormatUint(uint64(e.UID), 10)
	gidName := strconv.FormatUint(uint64(e.GID), 10)
	if u, err := osuser.LookupId(uidName); err == nil {
		uidName = u.Username
	}
	if g, err := osuser.LookupGroupId(gidName); err == nil {
		gidName = g.Name
	}
	if e.UserName != uidName {
		t.Fatalf("expected user name %q, got %q", uidName, e.UserName)
	}
	if e.GroupName != gidName {
		t.Fatalf("expected group name %q, got %q", gidName, e.GroupName)
	}
}

func TestServerSession_userNameFallback(t *testing.T) {
	sess := &ServerSession{
		lookupUserID: func(string) (*osuser.User, error) {
			return nil, fmt.Errorf("no such user")
		},
	}
	got := sess.userName(1000)
	if got != "1000" {
		t.Fatalf("expected numeric fallback, got %q", got)
	}
	// Cached result is returned on the second call.
	if sess.userNames[1000] != got {
		t.Fatalf("expected cached user name, got %q", sess.userNames[1000])
	}
}

func TestServerSession_userNameCaching(t *testing.T) {
	calls := 0
	sess := &ServerSession{
		lookupUserID: func(id string) (*osuser.User, error) {
			calls++
			return &osuser.User{Username: "alice"}, nil
		},
	}
	if got := sess.userName(1000); got != "alice" {
		t.Fatalf("unexpected user name: %q", got)
	}
	if got := sess.userName(1000); got != "alice" {
		t.Fatalf("unexpected cached user name: %q", got)
	}
	if calls != 1 {
		t.Fatalf("expected 1 lookup, got %d", calls)
	}
}

func TestServerSession_groupNameFallback(t *testing.T) {
	sess := &ServerSession{
		lookupGroupID: func(string) (*osuser.Group, error) {
			return nil, fmt.Errorf("no such group")
		},
	}
	got := sess.groupName(1001)
	if got != "1001" {
		t.Fatalf("expected numeric fallback, got %q", got)
	}
	// Cached result is returned on the second call.
	if sess.groupNames[1001] != got {
		t.Fatalf("expected cached group name, got %q", sess.groupNames[1001])
	}
}

func TestServerSession_groupNameCaching(t *testing.T) {
	calls := 0
	sess := &ServerSession{
		lookupGroupID: func(id string) (*osuser.Group, error) {
			calls++
			return &osuser.Group{Name: "staff"}, nil
		},
	}
	if got := sess.groupName(1001); got != "staff" {
		t.Fatalf("unexpected group name: %q", got)
	}
	if got := sess.groupName(1001); got != "staff" {
		t.Fatalf("unexpected cached group name: %q", got)
	}
	if calls != 1 {
		t.Fatalf("expected 1 lookup, got %d", calls)
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
	if resp.Info.UID != uint32(os.Getuid()) || resp.Info.GID != uint32(os.Getgid()) {
		t.Fatalf("unexpected ownership: %+v", resp.Info)
	}
	if resp.Info.UserName == "" || resp.Info.GroupName == "" {
		t.Fatalf("expected user/group names: %+v", resp.Info)
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
	if err := decodeResponseFrame(ch.Writes[0], &got); err != nil {
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
	e := FileInfo{Name: "foo", Size: 42, Mode: 0644, IsDir: false, ModTime: 1234567890, UID: 1000, GID: 1001, UserName: "alice", GroupName: "staff"}
	info := sftpFileInfoFromEntry(e)
	if info.Name() != "foo" || info.Size() != 42 || info.IsDir() || info.Mode() != 0644 {
		t.Fatalf("unexpected FileInfo: %+v", info)
	}
	f, ok := info.(*sftpFileInfo)
	if !ok {
		t.Fatalf("unexpected type: %T", info)
	}
	if f.uid != 1000 || f.gid != 1001 || f.userName != "alice" || f.groupName != "staff" {
		t.Fatalf("unexpected ownership: %+v", f)
	}
}

func TestFormatEntryRemote(t *testing.T) {
	info := sftpFileInfoFromEntry(FileInfo{
		Name:      "notes.txt",
		Size:      42,
		Mode:      0644,
		ModTime:   1700000000,
		UID:       1000,
		GID:       1001,
		UserName:  "alice",
		GroupName: "staff",
	})
	mtime := time.Unix(1700000000, 0).Format("Jan 02 15:04")
	want := "-rw-r--r-- alice" + strings.Repeat(" ", 6) + "staff" + strings.Repeat(" ", 14) + "42 " + mtime + " notes.txt"
	if got := formatEntry("notes.txt", info); got != want {
		t.Fatalf("unexpected format:\n got %q\nwant %q", got, want)
	}
}

func TestFormatEntryRemoteFallsBackToNumeric(t *testing.T) {
	info := sftpFileInfoFromEntry(FileInfo{Name: "x", Size: 1, Mode: 0600, ModTime: 0, UID: 1000, GID: 1001})
	got := formatEntry("x", info)
	if !strings.Contains(got, "1000") || !strings.Contains(got, "1001") {
		t.Fatalf("expected numeric fallback in %q", got)
	}
}

func TestFormatEntryLocal(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "local.txt")
	os.WriteFile(f, []byte("x"), 0644)
	info, err := os.Stat(f)
	if err != nil {
		t.Fatalf("stat error: %v", err)
	}
	got := formatEntry("local.txt", info)
	if !strings.Contains(got, "local.txt") {
		t.Fatalf("missing name in %q", got)
	}
	uid := strconv.FormatUint(uint64(os.Getuid()), 10)
	if u, err := osuser.LookupId(uid); err == nil {
		if !strings.Contains(got, u.Username) {
			t.Fatalf("missing user %q in %q", u.Username, got)
		}
	}
}

func TestFormatEntryNil(t *testing.T) {
	if got := formatEntry("orphan", nil); got != "orphan" {
		t.Fatalf("unexpected format: %q", got)
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
		makeResponseMsg(statResp),
		makeResponseMsg(chunk1),
		makeResponseMsg(chunk2),
		makeResponseMsg(done),
	)

	if err := downloadFile(ch, "remote.txt", localPath, true, nil); err != nil {
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
	ch := newMockChannel(makeResponseMsg(&Response{ID: 1, OK: false, Error: "no such file"}))
	err := downloadFile(ch, "missing", filepath.Join(t.TempDir(), "out"), true, nil)
	if err == nil {
		t.Fatal("expected error for stat failure")
	}
}

// TestDownloadFile_ServerErrorIncludesPath verifies that a server error
// reported without a path is enriched with the remote path on the client, so
// errors like "too many levels of symbolic links" identify the file.
func TestDownloadFile_ServerErrorIncludesPath(t *testing.T) {
	ch := newMockChannel(makeResponseMsg(&Response{ID: 1, OK: false, Error: "too many levels of symbolic links"}))
	err := downloadFile(ch, "loop/file.txt", filepath.Join(t.TempDir(), "out"), true, nil)
	if err == nil {
		t.Fatal("expected error from server")
	}
	if !strings.Contains(err.Error(), "loop/file.txt") {
		t.Fatalf("expected error to include the remote path, got: %v", err)
	}
}

// TestDownloadFile_ServerErrorWithPathNotDuplicated verifies that a server
// error that already carries the path is passed through unchanged.
func TestDownloadFile_ServerErrorWithPathNotDuplicated(t *testing.T) {
	const serverErr = "/remote/loop/file.txt: too many levels of symbolic links"
	ch := newMockChannel(makeResponseMsg(&Response{ID: 1, OK: false, Error: serverErr}))
	err := downloadFile(ch, "/remote/loop/file.txt", filepath.Join(t.TempDir(), "out"), true, nil)
	if err == nil || err.Error() != serverErr {
		t.Fatalf("expected unchanged server error, got: %v", err)
	}
}

// TestUploadFile_ServerErrorIncludesPath verifies that an upload rejection by
// the server is reported with the remote path it concerned.
func TestUploadFile_ServerErrorIncludesPath(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "local.txt")
	os.WriteFile(localPath, []byte("x"), 0644)

	ch := newMockChannel(makeResponseMsg(&Response{ID: 1, OK: false, Error: "too many levels of symbolic links"}))
	err := uploadFile(ch, localPath, "loop/out.txt", true, nil)
	if err == nil {
		t.Fatal("expected error from server")
	}
	if !strings.Contains(err.Error(), "loop/out.txt") {
		t.Fatalf("expected error to include the remote path, got: %v", err)
	}
}

func TestUploadFile(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "local.txt")
	content := []byte("upload me")
	os.WriteFile(localPath, content, 0644)

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true}),
	)

	// Verify that uploadFile sends the data through the channel without error.
	// The remote side would write the file; our mock just acknowledges.
	if err := uploadFile(ch, localPath, "remote.txt", true, nil); err != nil {
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
		makeResponseMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote-dir", IsDir: true}}),
		makeResponseMsg(&Response{ID: 2, OK: true, Entries: []FileInfo{{Name: "subdir", IsDir: true}, {Name: "file.txt", Size: 5, Mode: 0644}}}),
		makeResponseMsg(&Response{ID: 3, OK: true, Info: &FileInfo{Name: "subdir", IsDir: true}}),
		makeResponseMsg(&Response{ID: 4, OK: true, Entries: []FileInfo{{Name: "nested.txt", Size: 11, Mode: 0644}}}),
		makeResponseMsg(&Response{ID: 5, OK: true, Data: []byte("hello world")}),
		makeResponseMsg(&Response{ID: 6, OK: true, Data: []byte{}}),
		makeResponseMsg(&Response{ID: 7, OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{ID: 8, OK: true, Data: []byte{}}),
	)

	if err := downloadRecursive(ch, "remote-dir", localRoot, true, nil); err != nil {
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
		makeResponseMsg(&Response{ID: 1, OK: false, Error: "no such file"}),
		makeResponseMsg(&Response{ID: 2, OK: true}),
		makeResponseMsg(&Response{ID: 3, OK: true}),
		makeResponseMsg(&Response{ID: 4, OK: true, Info: &FileInfo{Name: "subdir", IsDir: true}}),
		makeResponseMsg(&Response{ID: 5, OK: true}),
	)

	if err := uploadRecursive(ch, localRoot, "remote-dir", true, nil); err != nil {
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
	err := uploadFile(ch, dirPath, "/remote/file", true, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot upload a directory") {
		t.Fatalf("expected directory upload error, got: %v", err)
	}
}

func TestDoRequest(t *testing.T) {
	want := &Response{ID: 7, OK: true, Path: "/tmp"}
	ch := newMockChannel(makeResponseMsg(want))
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
	if err := decodeRequestFrame(ch.Writes[0], &req); err != nil {
		t.Fatalf("unmarshal written request: %v", err)
	}
	if req.Cmd != "pwd" {
		t.Fatalf("unexpected written request: %+v", req)
	}
}

// --- Chunked transfer size boundary tests ---

func TestChunkSizeConstant(t *testing.T) {
	// Larger chunks amortise per-chunk framing and syscalls over more data,
	// which is what makes pipelined transfers fast; 128 KiB is a power of
	// two that keeps the in-flight transfer window (TransferWindow ×
	// ChunkSize) well under a few MiB per direction.
	if ChunkSize != 128*1024 {
		t.Fatalf("ChunkSize expected %d, got %d", 128*1024, ChunkSize)
	}
	if TransferWindow < 1 {
		t.Fatalf("TransferWindow must be at least 1, got %d", TransferWindow)
	}
}

// TestDownloadFileContentsPipelined verifies that the download keeps a window
// of read requests in flight instead of waiting for each chunk's response
// before asking for the next. The windowed mock channel refuses to answer
// until the whole window has been written, so a synchronous client would
// deadlock; the pipelined client sends the window up front and completes.
func TestDownloadFileContentsPipelined(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "out.bin")

	// Three full chunks, distinct per chunk so reassembly order is verifiable.
	const n = 3
	total := int64(n) * ChunkSize
	var msgs []ssh3Messages.Message
	for i := 0; i < n; i++ {
		msgs = append(msgs, makeResponseMsg(&Response{ID: uint64(i + 1), OK: true, Data: bytes.Repeat([]byte{byte('a' + i)}, ChunkSize)}))
	}
	// Each data response triggers a refill request beyond the end of the
	// file, which the server answers with an empty payload.
	for i := 0; i < n; i++ {
		msgs = append(msgs, makeResponseMsg(&Response{ID: uint64(n + i + 1), OK: true, Data: []byte{}}))
	}
	// The initial window is min(TransferWindow, n); the channel must see the
	// whole window before serving the first response.
	ch := newWindowedMockChannel(n, msgs...)

	if err := runWithTimeout(t, "pipelined download", func() error {
		return downloadFileContents(ch, "remote.bin", localPath, total, nil)
	}); err != nil {
		t.Fatalf("downloadFileContents error: %v", err)
	}

	got, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if len(got) != int(total) {
		t.Fatalf("expected %d bytes, got %d", total, len(got))
	}
	for i := 0; i < n; i++ {
		want := bytes.Repeat([]byte{byte('a' + i)}, ChunkSize)
		if !bytes.Equal(got[i*ChunkSize:(i+1)*ChunkSize], want) {
			t.Fatalf("chunk %d corrupted", i)
		}
	}

	// Every request must carry a chunk-aligned, strictly increasing offset
	// (the initial window plus the refills as the responses arrive).
	var reqs []Request
	for _, w := range ch.Writes {
		var req Request
		if err := decodeRequestFrame(w, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		if req.Cmd != "get" || req.Limit != ChunkSize || req.Offset%ChunkSize != 0 {
			t.Fatalf("unexpected request: %+v", req)
		}
		reqs = append(reqs, req)
	}
	for i := 1; i < len(reqs); i++ {
		if reqs[i].Offset <= reqs[i-1].Offset {
			t.Fatalf("offsets not strictly increasing: %+v", reqs)
		}
	}
}

// TestUploadFilePipelined mirrors TestDownloadFileContentsPipelined for the
// upload direction: the whole window of write requests must be sent before the
// first acknowledgement is consumed, and the offsets must be chunk-aligned.
func TestUploadFilePipelined(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "in.bin")

	const n = 3
	content := make([]byte, int64(n)*ChunkSize)
	for i := range content {
		content[i] = byte(i)
	}
	os.WriteFile(localPath, content, 0644)

	var msgs []ssh3Messages.Message
	for i := 0; i < n; i++ {
		msgs = append(msgs, makeResponseMsg(&Response{ID: uint64(i + 1), OK: true}))
	}
	ch := newWindowedMockChannel(n, msgs...)

	if err := runWithTimeout(t, "pipelined upload", func() error {
		return uploadFile(ch, localPath, "remote.bin", true, nil)
	}); err != nil {
		t.Fatalf("uploadFile error: %v", err)
	}

	if len(ch.Writes) != n {
		t.Fatalf("expected %d requests, got %d", n, len(ch.Writes))
	}
	for i, w := range ch.Writes {
		var req Request
		if err := decodeRequestFrame(w, &req); err != nil {
			t.Fatalf("unmarshal request %d: %v", i, err)
		}
		if req.Cmd != "put" || req.Offset != int64(i)*ChunkSize {
			t.Fatalf("request %d: expected put offset=%d, got %s offset=%d",
				i, i*ChunkSize, req.Cmd, req.Offset)
		}
		if !bytes.Equal(req.Data, content[i*ChunkSize:(i+1)*ChunkSize]) {
			t.Fatalf("request %d: chunk data corrupted", i)
		}
	}
}

// TestDownloadFileContentsShortFinalChunk verifies that a file whose size is
// not a multiple of the chunk size is reassembled correctly: every request
// except the last asks for a full chunk and the final response carries the
// short remainder.
func TestDownloadFileContentsShortFinalChunk(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "out.bin")

	const n = 3
	total := int64(n)*ChunkSize + 1234
	var msgs []ssh3Messages.Message
	for i := 0; i < n; i++ {
		msgs = append(msgs, makeResponseMsg(&Response{ID: uint64(i + 1), OK: true, Data: bytes.Repeat([]byte{byte('a' + i)}, ChunkSize)}))
	}
	msgs = append(msgs, makeResponseMsg(&Response{ID: 4, OK: true, Data: bytes.Repeat([]byte{'d'}, 1234)}))
	// The four data responses each trigger a refill request beyond the end of
	// the file, answered with an empty payload.
	for i := 0; i < 4; i++ {
		msgs = append(msgs, makeResponseMsg(&Response{ID: 5 + uint64(i), OK: true, Data: []byte{}}))
	}

	ch := newWindowedMockChannel(4, msgs...)
	if err := runWithTimeout(t, "short-final-chunk download", func() error {
		return downloadFileContents(ch, "remote.bin", localPath, total, nil)
	}); err != nil {
		t.Fatalf("downloadFileContents error: %v", err)
	}

	got, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if int64(len(got)) != total {
		t.Fatalf("expected %d bytes, got %d", total, len(got))
	}
	if !bytes.Equal(got[total-1234:], bytes.Repeat([]byte{'d'}, 1234)) {
		t.Fatal("final short chunk corrupted")
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

// TestServerHandleRequest_symlinkLoopIncludesPath verifies that syscall errors
// such as ELOOP ("too many levels of symbolic links") identify the filepath
// that caused them, both when the loop sits in an ancestor directory
// (checkAncestorExecute) and when the request target itself is the loop.
func TestServerHandleRequest_symlinkLoopIncludesPath(t *testing.T) {
	tmp := t.TempDir()
	loop := filepath.Join(tmp, "loop")
	if err := os.Mkdir(loop, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.Symlink("loop", filepath.Join(loop, "loop")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	sess := &ServerSession{currentDir: tmp}
	loopPath := filepath.Join(loop, "loop")

	// The ancestor tmp/loop/loop is a symlink loop: checkAncestorExecute
	// fails while traversing it and must report the path that failed.
	resp := sess.handleRequest(Request{Cmd: "ls", Path: "loop/loop/loop"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected symlink loop error, got %+v", resp)
	}
	if !strings.Contains(resp.Error, loopPath) {
		t.Fatalf("expected error to include path %s, got %q", loopPath, resp.Error)
	}
	if !strings.Contains(resp.Error, "symbolic links") {
		t.Fatalf("expected 'too many levels of symbolic links' error, got %q", resp.Error)
	}

	// The target itself is a symlink loop: the open fails on the final
	// component and must report the requested path.
	resp = sess.handleRequest(Request{Cmd: "get", Path: "loop/loop"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected symlink loop error, got %+v", resp)
	}
	if !strings.Contains(resp.Error, loopPath) {
		t.Fatalf("expected error to include path %s, got %q", loopPath, resp.Error)
	}
	if !strings.Contains(resp.Error, "symbolic links") {
		t.Fatalf("expected 'too many levels of symbolic links' error, got %q", resp.Error)
	}
}

// TestServerHandleRequest_putToDirectoryIncludesPath verifies that a put
// targeting an existing directory reports the path in its error.
func TestServerHandleRequest_putToDirectoryIncludesPath(t *testing.T) {
	tmp := t.TempDir()
	d := filepath.Join(tmp, "adir")
	if err := os.Mkdir(d, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "put", Path: "adir", Data: []byte("x")})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected put to directory to fail, got %+v", resp)
	}
	if !strings.Contains(resp.Error, d) {
		t.Fatalf("expected error to include path %s, got %q", d, resp.Error)
	}
	if !strings.Contains(resp.Error, "is a directory") {
		t.Fatalf("expected 'is a directory' error, got %q", resp.Error)
	}
}

// TestServerHandleRequest_missingFileIncludesPath verifies that a missing
// file is reported with its path for the commands that resolve it.
func TestServerHandleRequest_missingFileIncludesPath(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "missing.txt")
	sess := &ServerSession{currentDir: tmp}

	for _, cmd := range []string{"stat", "get", "rm", "ls", "cd"} {
		resp := sess.handleRequest(Request{Cmd: cmd, Path: "missing.txt"})
		if resp.OK || resp.Error == "" {
			t.Fatalf("expected error for %s of missing file, got %+v", cmd, resp)
		}
		if !strings.Contains(resp.Error, missing) {
			t.Fatalf("%s: expected error to include path %s, got %q", cmd, missing, resp.Error)
		}
	}
}

// --- Integration-style end-to-end test for server handling two requests ---

func TestServeChannel_TwoRequests(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("alpha"), 0644)

	req1 := Request{Cmd: "pwd"}
	req2 := Request{Cmd: "ls", Path: "."}
	b1 := EncodeRequest(&req1)
	b2 := EncodeRequest(&req2)

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
	decodeResponseFrame(ch.Writes[0], &resp1)
	decodeResponseFrame(ch.Writes[1], &resp2)

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

func TestServeChannel_ChunkedRequest(t *testing.T) {
	tmp := t.TempDir()

	// Build a put request whose frame exceeds one channel data message, so
	// the request arrives split across several messages. The server must
	// reassemble it before handling, mirroring the response-side reassembly.
	payload := bytes.Repeat([]byte("abcdefghij"), 3000) // 30000 bytes of data
	req := Request{Cmd: "put", Path: filepath.Join(tmp, "big.bin"), Data: payload}
	raw := EncodeRequest(&req)
	msgs := splitIntoChannelMessages(raw)
	if len(msgs) < 2 {
		t.Fatalf("test request too small to be split across messages")
	}

	ch := newMockChannel(msgs...)
	user := currentTestUser(tmp)
	ServeChannel(nil, user, ch)

	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 response, got %d", len(ch.Writes))
	}
	var resp Response
	if err := decodeResponseFrame(ch.Writes[0], &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok response, got %+v", resp)
	}

	got, err := os.ReadFile(filepath.Join(tmp, "big.bin"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("file content mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// queuedMockChannel is a mock channel that returns the next queued message on
// each NextMessage call. It is used to drive concurrent SFTP sessions from
// a goroutine without pre-populating the full message list. The embedded
// MockChannel is accessed through mutex-protected wrappers so the test is safe
// under the race detector.
type queuedMockChannel struct {
	*ssh3.MockChannel
	mu       sync.Mutex
	messages []ssh3Messages.Message
	closed   bool
	cond     *sync.Cond
}

func newQueuedMockChannel() *queuedMockChannel {
	q := &queuedMockChannel{MockChannel: ssh3.NewMockChannel()}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *queuedMockChannel) enqueue(msgs ...ssh3Messages.Message) {
	q.mu.Lock()
	q.messages = append(q.messages, msgs...)
	q.cond.Broadcast()
	q.mu.Unlock()
}

func (q *queuedMockChannel) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.cond.Broadcast()
	q.MockChannel.Close()
}

func (q *queuedMockChannel) NextMessage() (ssh3Messages.Message, error) {
	q.mu.Lock()
	for len(q.messages) == 0 && !q.closed {
		q.cond.Wait()
	}
	if q.closed {
		q.mu.Unlock()
		return nil, io.EOF
	}
	msg := q.messages[0]
	q.messages = q.messages[1:]
	q.mu.Unlock()
	return msg, nil
}

func (q *queuedMockChannel) WriteData(dataBuf []byte, dataType ssh3Messages.SSHDataType) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.MockChannel.WriteData(dataBuf, dataType)
}

func (q *queuedMockChannel) Writes() [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.MockChannel.Writes
}

func (q *queuedMockChannel) IsClosed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.MockChannel.Closed
}

// waitResponses blocks until at least n responses have been written to the
// channel. It is used to avoid closing the channel before the server has
// processed all queued requests.
func (q *queuedMockChannel) waitResponses(n int) {
	for {
		q.mu.Lock()
		if len(q.MockChannel.Writes) >= n {
			q.mu.Unlock()
			return
		}
		q.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
}

func writeRequest(req Request) *ssh3Messages.DataOrExtendedDataMessage {
	return makeDataMsg(EncodeRequest(&req))
}

func readResponses(t *testing.T, writes [][]byte, n int) []Response {
	t.Helper()
	if len(writes) != n {
		t.Fatalf("expected %d responses, got %d", n, len(writes))
	}
	resps := make([]Response, n)
	for i, w := range writes {
		if err := decodeResponseFrame(w, &resps[i]); err != nil {
			t.Fatalf("unmarshal response %d: %v", i, err)
		}
	}
	return resps
}

// TestConcurrentServeChannels_MultipleUsers validates that two independent SFTP
// sessions can be served concurrently without interfering with each other's
// state or filesystem view.
func TestConcurrentServeChannels_MultipleUsers(t *testing.T) {
	tmpA := t.TempDir()
	tmpB := t.TempDir()
	os.WriteFile(filepath.Join(tmpA, "a.txt"), []byte("alpha"), 0644)
	os.WriteFile(filepath.Join(tmpB, "b.txt"), []byte("bravo"), 0644)

	chA := newQueuedMockChannel()
	chB := newQueuedMockChannel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ServeChannel(nil, currentTestUser(tmpA), chA)
	}()
	go func() {
		defer wg.Done()
		ServeChannel(nil, currentTestUser(tmpB), chB)
	}()

	// Send interleaved requests to both channels.
	chA.enqueue(writeRequest(Request{ID: 1, Cmd: "pwd"}))
	chB.enqueue(writeRequest(Request{ID: 1, Cmd: "pwd"}))
	chA.enqueue(writeRequest(Request{ID: 2, Cmd: "ls", Path: "."}))
	chB.enqueue(writeRequest(Request{ID: 2, Cmd: "ls", Path: "."}))
	chA.enqueue(writeRequest(Request{ID: 3, Cmd: "stat", Path: "a.txt"}))
	chB.enqueue(writeRequest(Request{ID: 3, Cmd: "stat", Path: "b.txt"}))
	chA.waitResponses(3)
	chB.waitResponses(3)
	chA.Close()
	chB.Close()

	wg.Wait()

	respsA := readResponses(t, chA.Writes(), 3)
	respsB := readResponses(t, chB.Writes(), 3)

	if !respsA[0].OK || respsA[0].Path != tmpA {
		t.Fatalf("user A pwd response: %+v", respsA[0])
	}
	if !respsB[0].OK || respsB[0].Path != tmpB {
		t.Fatalf("user B pwd response: %+v", respsB[0])
	}

	if !respsA[1].OK || len(respsA[1].Entries) != 1 || respsA[1].Entries[0].Name != "a.txt" {
		t.Fatalf("user A ls response: %+v", respsA[1])
	}
	if !respsB[1].OK || len(respsB[1].Entries) != 1 || respsB[1].Entries[0].Name != "b.txt" {
		t.Fatalf("user B ls response: %+v", respsB[1])
	}

	if !respsA[2].OK || respsA[2].Info == nil || respsA[2].Info.Name != "a.txt" || respsA[2].Info.Size != 5 {
		t.Fatalf("user A stat response: %+v", respsA[2])
	}
	if !respsB[2].OK || respsB[2].Info == nil || respsB[2].Info.Name != "b.txt" || respsB[2].Info.Size != 5 {
		t.Fatalf("user B stat response: %+v", respsB[2])
	}

	if !chA.IsClosed() || !chB.IsClosed() {
		t.Fatalf("expected both channels to close")
	}
}

// TestConcurrentServeChannels_SharedDirectory validates that two SFTP sessions
// in the same directory see consistent, isolated request results even when their
// requests are interleaved.
func TestConcurrentServeChannels_SharedDirectory(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "shared.txt"), []byte("shared"), 0644)

	chA := newQueuedMockChannel()
	chB := newQueuedMockChannel()

	user := currentTestUser(tmp)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ServeChannel(nil, user, chA)
	}()
	go func() {
		defer wg.Done()
		ServeChannel(nil, user, chB)
	}()

	// Queue writes from both sessions to a shared directory, then wait for both
	// puts to complete before listing so the directory contents are deterministic.
	chA.enqueue(writeRequest(Request{ID: 1, Cmd: "put", Path: "A.txt", Data: []byte("A1")}))
	chB.enqueue(writeRequest(Request{ID: 1, Cmd: "put", Path: "B.txt", Data: []byte("B1")}))
	chA.waitResponses(1)
	chB.waitResponses(1)
	chA.enqueue(writeRequest(Request{ID: 2, Cmd: "ls", Path: "."}))
	chB.enqueue(writeRequest(Request{ID: 2, Cmd: "ls", Path: "."}))
	chA.enqueue(writeRequest(Request{ID: 3, Cmd: "stat", Path: "shared.txt"}))
	chB.enqueue(writeRequest(Request{ID: 3, Cmd: "stat", Path: "shared.txt"}))
	chA.waitResponses(3)
	chB.waitResponses(3)
	chA.Close()
	chB.Close()

	wg.Wait()

	respsA := readResponses(t, chA.Writes(), 3)
	respsB := readResponses(t, chB.Writes(), 3)

	for i, resp := range respsA {
		if !resp.OK {
			t.Fatalf("user A response %d failed: %+v", i, resp)
		}
	}
	for i, resp := range respsB {
		if !resp.OK {
			t.Fatalf("user B response %d failed: %+v", i, resp)
		}
	}

	if len(respsA[1].Entries) != 3 {
		t.Fatalf("expected 3 directory entries for user A, got %d: %+v", len(respsA[1].Entries), respsA[1].Entries)
	}
	if len(respsB[1].Entries) != 3 {
		t.Fatalf("expected 3 directory entries for user B, got %d: %+v", len(respsB[1].Entries), respsB[1].Entries)
	}

	if respsA[2].Info.Size != 6 || respsB[2].Info.Size != 6 {
		t.Fatalf("shared file size inconsistent: A=%d B=%d", respsA[2].Info.Size, respsB[2].Info.Size)
	}
}

// TestConcurrentStress_ReadWrite validates that many concurrent SFTP sessions
// can read and write independent files without data corruption.
func TestConcurrentStress_ReadWrite(t *testing.T) {
	const numSessions = 10
	const numFiles = 5

	var wg sync.WaitGroup
	errors := make(chan string, numSessions*numFiles*2)

	for i := 0; i < numSessions; i++ {
		tmp := t.TempDir()
		user := currentTestUser(tmp)
		ch := newMockChannel()

		// Pre-populate messages: one put per file, then one get per file.
		var msgs []ssh3Messages.Message
		for f := 0; f < numFiles; f++ {
			content := []byte(strings.Repeat(string(byte('a'+f)), 1024))
			msgs = append(msgs, writeRequest(Request{ID: uint64(f) + 1, Cmd: "put", Path: fmt.Sprintf("file%d.txt", f), Data: content}))
		}
		for f := 0; f < numFiles; f++ {
			msgs = append(msgs, writeRequest(Request{ID: uint64(numFiles + f + 1), Cmd: "get", Path: fmt.Sprintf("file%d.txt", f)}))
		}

		ch = ssh3.NewMockChannel(msgs...)

		wg.Add(1)
		go func(idx int, ch *ssh3.MockChannel, tmp string) {
			defer wg.Done()
			ServeChannel(nil, user, ch)

			resps := readResponses(t, ch.Writes, numFiles*2)
			for f := 0; f < numFiles; f++ {
				put := resps[f]
				get := resps[numFiles+f]
				if !put.OK {
					errors <- fmt.Sprintf("session %d put %d failed: %s", idx, f, put.Error)
				}
				if !get.OK {
					errors <- fmt.Sprintf("session %d get %d failed: %s", idx, f, get.Error)
					continue
				}
				want := []byte(strings.Repeat(string(byte('a'+f)), 1024))
				if !bytes.Equal(get.Data, want) {
					errors <- fmt.Sprintf("session %d file %d data mismatch", idx, f)
				}
			}
		}(i, ch, tmp)
	}

	wg.Wait()
	close(errors)

	var errList []string
	for e := range errors {
		errList = append(errList, e)
	}
	if len(errList) > 0 {
		t.Fatalf("concurrent stress errors:\n%s", strings.Join(errList, "\n"))
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

// captureStdout runs fn while routing standard output to a buffer, returning
// whatever fn printed to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close write end: %v", err)
	}
	os.Stdout = old

	// w is closed, so the goroutine's ReadAll unblocks and sends the captured
	// buffer; a plain receive cannot deadlock.
	return <-done
}

func TestGlobSplit(t *testing.T) {
	cases := []struct {
		arg         string
		wantDir     string
		wantPattern string
		wantOK      bool
	}{
		{"", "", "", false},
		{"plain", "", "", false},
		{"path/plain", "", "", false},
		{"a/b.c", "", "", false},
		{"test*", "", "test*", true},
		{"path/test*", "path", "test*", true},
		{"*.txt", "", "*.txt", true},
		{"[abc]", "", "[abc]", true},
		{"f?o", "", "f?o", true},
		{"dir/b*c", "dir", "b*c", true},
		{"/home/test*", "/home", "test*", true},
	}
	for _, c := range cases {
		dir, pat, ok := globSplit(c.arg)
		if dir != c.wantDir || pat != c.wantPattern || ok != c.wantOK {
			t.Errorf("globSplit(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.arg, dir, pat, ok, c.wantDir, c.wantPattern, c.wantOK)
		}
	}
}

func lsEntries(names ...string) []FileInfo {
	out := make([]FileInfo, 0, len(names))
	for _, n := range names {
		out = append(out, FileInfo{Name: n})
	}
	return out
}

func TestClientDoLsNoArg(t *testing.T) {
	ch := newMockChannel(makeResponseMsg(&Response{
		OK:      true,
		Entries: lsEntries("."),
	}))
	if err := doLs(ch, "/remote", []string{"ls"}); err != nil {
		t.Fatalf("doLs error: %v", err)
	}
	var got Request
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote" {
		t.Fatalf("expected ls /remote, got %s %q", got.Cmd, got.Path)
	}
}

func TestClientDoLsWildcard(t *testing.T) {
	ch := newMockChannel(makeResponseMsg(&Response{
		OK:      true,
		Entries: lsEntries("atest", "test", "testa", "test2", "nope"),
	}))
	out := captureStdout(t, func() {
		if err := doLs(ch, "/remote/path", []string{"ls", "test*"}); err != nil {
			t.Fatalf("doLs error: %v", err)
		}
	})

	var got Request
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote/path" {
		t.Fatalf("expected ls /remote/path, got %s %q", got.Cmd, got.Path)
	}
	// Only entries whose final component matches test* must be printed.
	for _, want := range []string{"test", "testa", "test2"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
	// Entries that do not match must not be listed. Neither "atest" nor "nope"
	// is a substring of any matching name, so we can assert their absence.
	if strings.Contains(out, "atest") || strings.Contains(out, "nope") {
		t.Errorf("unexpected non-matching entry in output:\n%s", out)
	}
	lines := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines++
		}
	}
	if lines != 3 {
		t.Errorf("expected 3 matching entries, got %d:\n%s", lines, out)
	}
}

func TestClientDoLsNoMatch(t *testing.T) {
	ch := newMockChannel(makeResponseMsg(&Response{
		OK:      true,
		Entries: lsEntries("one", "two"),
	}))
	out := captureStdout(t, func() {
		if err := doLs(ch, "/remote", []string{"ls", "zzz*"}); err != nil {
			t.Fatalf("doLs error: %v", err)
		}
	})
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected no output for non-matching glob, got:\n%s", out)
	}
}

func TestClientDoLsInvalidPattern(t *testing.T) {
	ch := newMockChannel(makeResponseMsg(&Response{OK: true, Entries: lsEntries("a")}))
	err := doLs(ch, "/remote", []string{"ls", "["})
	if err == nil {
		t.Fatal("expected error for invalid glob pattern")
	}
}

func TestClientDoGetNoGlob(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "remote.txt", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote", []string{"get", "remote.txt"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}

	var got Request
	if len(ch.Writes) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(ch.Writes))
	}
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "stat" || got.Path != "/remote/remote.txt" {
		t.Fatalf("expected stat /remote/remote.txt, got %s %q", got.Cmd, got.Path)
	}
	content, err := os.ReadFile(filepath.Join(localDir, "remote.txt"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}
}

func TestClientDoGetWildcard(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(
		makeResponseMsg(&Response{OK: true, Entries: lsEntries("atest", "test", "testa", "nope")}),
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "test", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "testa", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("world")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote/path", []string{"get", "test*"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}

	var got Request
	if len(ch.Writes) != 7 {
		t.Fatalf("expected 7 requests, got %d", len(ch.Writes))
	}
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote/path" {
		t.Fatalf("expected ls /remote/path, got %s %q", got.Cmd, got.Path)
	}

	// Only entries whose final component matches test* must be downloaded.
	for name, want := range map[string]string{"test": "hello", "testa": "world"} {
		content, err := os.ReadFile(filepath.Join(localDir, name))
		if err != nil {
			t.Fatalf("read downloaded %s: %v", name, err)
		}
		if string(content) != want {
			t.Errorf("unexpected content for %s: %q", name, content)
		}
	}
	// Entries that do not match must not be downloaded.
	if _, err := os.Stat(filepath.Join(localDir, "atest")); !os.IsNotExist(err) {
		t.Errorf("expected no download for non-matching entry, stat err: %v", err)
	}
}

func TestClientDoGetNoMatch(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(makeResponseMsg(&Response{
		OK:      true,
		Entries: lsEntries("one", "two"),
	}))

	if err := doGet(ch, localDir, "/remote", []string{"get", "zzz*"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}
	if len(ch.Writes) != 1 {
		t.Fatalf("expected only the ls request, got %d", len(ch.Writes))
	}
	entries, err := os.ReadDir(localDir)
	if err != nil {
		t.Fatalf("read local dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no downloads for non-matching glob, got %d files", len(entries))
	}
}

func TestClientDoGetInvalidPattern(t *testing.T) {
	ch := newMockChannel(makeResponseMsg(&Response{OK: true, Entries: lsEntries("a")}))
	err := doGet(ch, t.TempDir(), "/remote", []string{"get", "["}, true, nil)
	if err == nil {
		t.Fatal("expected error for invalid glob pattern")
	}
}

func TestClientDoGetRecursiveDir(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "d", IsDir: true}}),
		makeResponseMsg(&Response{OK: true, Entries: []FileInfo{{Name: "f.txt", Size: 5, Mode: 0644}}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote", []string{"get", "-r", "d"}, true, nil); err != nil {
		t.Fatalf("doGet -r dir error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(localDir, "d", "f.txt"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}
}

// TestClientDoGetRecursivePermissionDenied exercises get -r on a directory
// containing a mix of readable files and files the server refuses to read
// (permission denied): each denied file is reported and skipped, and every
// readable file is still downloaded. secret1.bin is larger than one chunk so
// its read window has several in-flight requests, all of which the server
// denies: the client must drain them so they are not mistaken for the next
// file's responses.
func TestClientDoGetRecursivePermissionDenied(t *testing.T) {
	localDir := t.TempDir()

	// A large denied file spans three chunks: three read requests go out and
	// the server denies all three.
	bigSize := int64(2*ChunkSize + 10)

	ch := newMockChannel(
		// stat of the top-level directory.
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "d", IsDir: true}}),
		// ls of the directory, mixing readable and unreadable files.
		makeResponseMsg(&Response{OK: true, Entries: []FileInfo{
			{Name: "ok1.txt", Size: 2, Mode: 0644},
			{Name: "secret1.bin", Size: bigSize, Mode: 0000},
			{Name: "ok2.txt", Size: 3, Mode: 0644},
			{Name: "secret2.txt", Size: 1, Mode: 0000},
			{Name: "ok3.txt", Size: 3, Mode: 0644},
		}}),
		// The download of ok1.txt succeeds.
		makeResponseMsg(&Response{OK: true, Data: []byte("O1")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
		// The server denies all three reads of secret1.bin.
		makeResponseMsg(&Response{OK: false, Error: "secret1.bin: permission denied"}),
		makeResponseMsg(&Response{OK: false, Error: "secret1.bin: permission denied"}),
		makeResponseMsg(&Response{OK: false, Error: "secret1.bin: permission denied"}),
		// The download of ok2.txt succeeds, proving the drained responses of
		// secret1.bin were not mistaken for its own.
		makeResponseMsg(&Response{OK: true, Data: []byte("OK2")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
		// The server refuses the single read of secret2.txt.
		makeResponseMsg(&Response{OK: false, Error: "secret2.txt: permission denied"}),
		// The download of ok3.txt succeeds.
		makeResponseMsg(&Response{OK: true, Data: []byte("OK3")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote", []string{"get", "-r", "d"}, true, nil); err != nil {
		t.Fatalf("doGet -r error: %v", err)
	}

	// Every readable file must be downloaded with its own content.
	want := map[string]string{
		"ok1.txt":     "O1",
		"ok2.txt":     "OK2",
		"ok3.txt":     "OK3",
		"secret1.bin": "",
		"secret2.txt": "",
	}
	for name, content := range want {
		got, err := os.ReadFile(filepath.Join(localDir, "d", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != content {
			t.Fatalf("%s: unexpected content %q, want %q", name, got, content)
		}
	}
}

// TestClientDoGetRecursiveWildcard exercises get -r with a glob source: the
// parent directory is listed, entries matching the pattern are transferred
// recursively (directories walked, files downloaded), and non-matching entries
// are skipped, mirroring the wildcard behavior of a non-recursive get.
func TestClientDoGetRecursiveWildcard(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(
		// ls of the globbed parent directory: "atest" does not match "test*",
		// "test" is a directory and "testa" a file.
		makeResponseMsg(&Response{OK: true, Entries: []FileInfo{
			{Name: "atest"},
			{Name: "test", IsDir: true},
			{Name: "testa", Size: 5, Mode: 0644},
		}}),
		// Recursing into the matched directory "test".
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "test", IsDir: true}}),
		makeResponseMsg(&Response{OK: true, Entries: []FileInfo{{Name: "nested.txt", Size: 11, Mode: 0644}}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello world")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
		// Downloading the matched file "testa".
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "testa", Size: 5, Mode: 0644}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("world")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote/path", []string{"get", "-r", "test*"}, true, nil); err != nil {
		t.Fatalf("doGet -r wildcard error: %v", err)
	}

	// Only entries whose final component matches test* must be transferred, and
	// matched directories must be downloaded recursively.
	nested, err := os.ReadFile(filepath.Join(localDir, "test", "nested.txt"))
	if err != nil {
		t.Fatalf("read nested file: %v", err)
	}
	if string(nested) != "hello world" {
		t.Fatalf("unexpected nested content: %q", nested)
	}
	content, err := os.ReadFile(filepath.Join(localDir, "testa"))
	if err != nil {
		t.Fatalf("read matched file: %v", err)
	}
	if string(content) != "world" {
		t.Fatalf("unexpected file content: %q", content)
	}
	// Entries that do not match must not be downloaded.
	if _, err := os.Stat(filepath.Join(localDir, "atest")); !os.IsNotExist(err) {
		t.Errorf("expected no download for non-matching entry, stat err: %v", err)
	}

	// Requests: glob ls, then recursion into "test" (stat, ls, 2 get chunks),
	// then download of "testa" (stat, 2 get chunks).
	if len(ch.Writes) != 8 {
		t.Fatalf("expected 8 requests, got %d", len(ch.Writes))
	}
	var got Request
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote/path" {
		t.Fatalf("expected ls /remote/path, got %s %q", got.Cmd, got.Path)
	}
}

func TestClientDoGetRecursiveWildcardNoMatch(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(makeResponseMsg(&Response{
		OK:      true,
		Entries: lsEntries("one", "two"),
	}))

	if err := doGet(ch, localDir, "/remote", []string{"get", "-r", "zzz*"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}
	if len(ch.Writes) != 1 {
		t.Fatalf("expected only the ls request, got %d", len(ch.Writes))
	}
	entries, err := os.ReadDir(localDir)
	if err != nil {
		t.Fatalf("read local dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no downloads for non-matching recursive glob, got %d files", len(entries))
	}
}

func TestClientDoPutWildcard(t *testing.T) {
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "a.txt"), []byte("A"), 0644)
	os.WriteFile(filepath.Join(localDir, "b.txt"), []byte("B"), 0644)
	os.WriteFile(filepath.Join(localDir, "c.log"), []byte("C"), 0644)

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true}), // put a.txt
		makeResponseMsg(&Response{ID: 2, OK: true}), // put b.txt
	)

	if err := doPut(ch, localDir, "/remote", []string{"put", "*.txt"}, true, nil); err != nil {
		t.Fatalf("doPut error: %v", err)
	}

	if len(ch.Writes) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(ch.Writes))
	}
	var got Request
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/remote/a.txt" {
		t.Errorf("expected put /remote/a.txt, got %s %q", got.Cmd, got.Path)
	}
	if err := decodeRequestFrame(ch.Writes[1], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/remote/b.txt" {
		t.Errorf("expected put /remote/b.txt, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoPutWildcardSubdirPattern verifies that a put source whose
// pattern spans a directory (e.g. sub/*.txt) is expanded against the local
// filesystem, uploading each match under its basename.
func TestClientDoPutWildcardSubdirPattern(t *testing.T) {
	localDir := t.TempDir()
	os.MkdirAll(filepath.Join(localDir, "sub"), 0o755)
	os.WriteFile(filepath.Join(localDir, "sub", "one.txt"), []byte("1"), 0644)
	os.WriteFile(filepath.Join(localDir, "sub", "two.TXT"), []byte("2"), 0644)
	os.WriteFile(filepath.Join(localDir, "top.txt"), []byte("T"), 0644)

	ch := newMockChannel(makeResponseMsg(&Response{ID: 1, OK: true}))

	if err := doPut(ch, localDir, "/remote", []string{"put", "sub/*.txt"}, true, nil); err != nil {
		t.Fatalf("doPut error: %v", err)
	}
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	var got Request
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/remote/one.txt" {
		t.Fatalf("expected put /remote/one.txt, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoPutWildcardToRemoteDir verifies that a multi-match put to an
// existing remote directory uploads each source into that directory under its
// own basename.
func TestClientDoPutWildcardToRemoteDir(t *testing.T) {
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "a.log"), []byte("A"), 0644)
	os.WriteFile(filepath.Join(localDir, "b.log"), []byte("B"), 0644)

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "logs", IsDir: true}}), // stat /remote/logs
		makeResponseMsg(&Response{ID: 2, OK: true}),                                             // put a.log
		makeResponseMsg(&Response{ID: 3, OK: true}),                                             // put b.log
	)

	if err := doPut(ch, localDir, "/remote", []string{"put", "*.log", "logs"}, true, nil); err != nil {
		t.Fatalf("doPut error: %v", err)
	}

	if len(ch.Writes) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(ch.Writes))
	}
	var got Request
	if err := decodeRequestFrame(ch.Writes[1], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/remote/logs/a.log" {
		t.Errorf("expected put /remote/logs/a.log, got %s %q", got.Cmd, got.Path)
	}
	if err := decodeRequestFrame(ch.Writes[2], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/remote/logs/b.log" {
		t.Errorf("expected put /remote/logs/b.log, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoPutWildcardToNonDirectory verifies that a multi-match put to a
// non-directory remote target fails without uploading anything.
func TestClientDoPutWildcardToNonDirectory(t *testing.T) {
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "a.log"), []byte("A"), 0644)
	os.WriteFile(filepath.Join(localDir, "b.log"), []byte("B"), 0644)

	ch := newMockChannel(makeResponseMsg(&Response{ID: 1, OK: false, Error: "no such file"}))

	err := doPut(ch, localDir, "/remote", []string{"put", "*.log", "logs"}, true, nil)
	if err == nil {
		t.Fatal("expected error for multi-match put to non-directory")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestClientDoPutRecursivePermissionDenied exercises put -r on a directory
// containing a mix of uploadable files and files the server refuses to write
// (permission denied): each denied file is reported and skipped, and every
// uploadable file is still uploaded. sa.bin is larger than one chunk so its
// write window has several in-flight requests, all of which the server
// denies: the client must drain them so they are not mistaken for the next
// file's responses. sc.txt sorts after the denied files, so it proves the
// drained responses of sa.bin were not mistaken for its own.
func TestClientDoPutRecursivePermissionDenied(t *testing.T) {
	localDir := t.TempDir()
	root := filepath.Join(localDir, "d")
	os.MkdirAll(root, 0o755)

	// A large denied file spans three chunks: three write requests go out and
	// the server denies all three.
	bigSize := int64(2*ChunkSize + 10)
	os.WriteFile(filepath.Join(root, "ok1.txt"), []byte("O1"), 0644)
	os.WriteFile(filepath.Join(root, "ok2.txt"), []byte("OK2"), 0644)
	os.WriteFile(filepath.Join(root, "ok3.txt"), []byte("OK3"), 0644)
	os.WriteFile(filepath.Join(root, "sa.bin"), bytes.Repeat([]byte("s"), int(bigSize)), 0644)
	os.WriteFile(filepath.Join(root, "sb.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(root, "sc.txt"), []byte("SC"), 0644)

	ch := newMockChannel(
		// stat of the top-level directory.
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "d", IsDir: true}}),
		// The uploads of ok1.txt, ok2.txt and ok3.txt succeed.
		makeResponseMsg(&Response{OK: true}),
		makeResponseMsg(&Response{OK: true}),
		makeResponseMsg(&Response{OK: true}),
		// The server denies all three writes of sa.bin.
		makeResponseMsg(&Response{OK: false, Error: "sa.bin: permission denied"}),
		makeResponseMsg(&Response{OK: false, Error: "sa.bin: permission denied"}),
		makeResponseMsg(&Response{OK: false, Error: "sa.bin: permission denied"}),
		// The server refuses the single write of sb.txt.
		makeResponseMsg(&Response{OK: false, Error: "sb.txt: permission denied"}),
		// The upload of sc.txt succeeds, proving the drained responses of
		// sa.bin were not mistaken for its own.
		makeResponseMsg(&Response{OK: true}),
	)

	if err := doPut(ch, localDir, "/remote", []string{"put", "-r", "d"}, true, nil); err != nil {
		t.Fatalf("doPut -r error: %v", err)
	}

	// Every pre-programmed response must have been consumed: the denied
	// file's in-flight responses were drained rather than left to be
	// mistaken for the next file's, and every uploadable file was
	// transferred.
	if ch.MsgIndex != len(ch.NextMsgs) {
		t.Fatalf("expected all %d responses to be consumed, got %d: the denied file's in-flight responses were not drained", len(ch.NextMsgs), ch.MsgIndex)
	}

	// The uploadable files must have been written to the server; the denied
	// ones are reported and skipped but their requests are still sent.
	var got Request
	var paths []string
	for _, w := range ch.Writes {
		if err := decodeRequestFrame(w, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Cmd == "put" {
			paths = append(paths, got.Path)
		}
	}
	for _, want := range []string{
		"/remote/d/ok1.txt",
		"/remote/d/ok2.txt",
		"/remote/d/ok3.txt",
		"/remote/d/sc.txt",
	} {
		found := false
		for _, p := range paths {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected put of %s, got puts %v", want, paths)
		}
	}
}

// TestClientDoPutRecursivePermissionDeniedWildcard exercises put -r with a
// glob source where one match is denied by the server: the denied match is
// reported and skipped and the remaining matches are still uploaded,
// mirroring the permission handling of a recursive get.
func TestClientDoPutRecursivePermissionDeniedWildcard(t *testing.T) {
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "a.txt"), []byte("A"), 0644)
	os.WriteFile(filepath.Join(localDir, "b.txt"), []byte("B"), 0644)
	os.WriteFile(filepath.Join(localDir, "c.txt"), []byte("C"), 0644)

	ch := newMockChannel(
		// The upload of a.txt succeeds.
		makeResponseMsg(&Response{OK: true}),
		// The server refuses to write b.txt.
		makeResponseMsg(&Response{OK: false, Error: "b.txt: permission denied"}),
		// The upload of c.txt succeeds.
		makeResponseMsg(&Response{OK: true}),
	)

	if err := doPut(ch, localDir, "/remote", []string{"put", "-r", "*.txt"}, true, nil); err != nil {
		t.Fatalf("doPut -r wildcard error: %v", err)
	}

	if ch.MsgIndex != len(ch.NextMsgs) {
		t.Fatalf("expected all %d responses to be consumed, got %d", len(ch.NextMsgs), ch.MsgIndex)
	}

	var got Request
	var paths []string
	for _, w := range ch.Writes {
		if err := decodeRequestFrame(w, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Cmd == "put" {
			paths = append(paths, got.Path)
		}
	}
	for _, want := range []string{"/remote/a.txt", "/remote/c.txt"} {
		found := false
		for _, p := range paths {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected put of %s, got puts %v", want, paths)
		}
	}
}

// TestClientDoPutSingleToRemoteDir verifies that a single-source put to an
// existing remote directory copies the file into it under its own basename.
func TestClientDoPutSingleToRemoteDir(t *testing.T) {
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "a.txt"), []byte("A"), 0644)

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "dir", IsDir: true}}),
		makeResponseMsg(&Response{ID: 2, OK: true}),
	)

	if err := doPut(ch, localDir, "/remote", []string{"put", "a.txt", "dir"}, true, nil); err != nil {
		t.Fatalf("doPut error: %v", err)
	}
	if len(ch.Writes) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(ch.Writes))
	}
	var got Request
	if err := decodeRequestFrame(ch.Writes[1], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/remote/dir/a.txt" {
		t.Fatalf("expected put /remote/dir/a.txt, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoPutSingleToNewName verifies that a single-source put to a target
// that is neither an existing directory nor slash-terminated uses the target
// as the remote file name verbatim.
func TestClientDoPutSingleToNewName(t *testing.T) {
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "a.txt"), []byte("A"), 0644)

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: false, Error: "no such file"}),
		makeResponseMsg(&Response{ID: 2, OK: true}),
	)

	if err := doPut(ch, localDir, "/remote", []string{"put", "a.txt", "newname"}, true, nil); err != nil {
		t.Fatalf("doPut error: %v", err)
	}
	if len(ch.Writes) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(ch.Writes))
	}
	var got Request
	if err := decodeRequestFrame(ch.Writes[1], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/remote/newname" {
		t.Fatalf("expected put /remote/newname, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoPutEscapedGlob verifies that a glob metacharacter escaped with a
// backslash is matched literally against the local filesystem, so a file named
// "star*file" uploads as itself rather than being globbed.
func TestClientDoPutEscapedGlob(t *testing.T) {
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "star*file"), []byte("S"), 0644)

	ch := newMockChannel(makeResponseMsg(&Response{ID: 1, OK: true}))

	// parts[1] is what makeargv produces for the typed `star\*file`.
	if err := doPut(ch, localDir, "/remote", []string{"put", `star\*file`}, true, nil); err != nil {
		t.Fatalf("doPut error: %v", err)
	}
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	var got Request
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/remote/star*file" {
		t.Fatalf("expected put /remote/star*file, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoPutQuotedMetachar verifies the full parsing pipeline: a glob
// metacharacter typed inside quotes is escaped by makeargv and then matched
// literally by the local glob, so put 'star*file' uploads the literal file
// (the same convention the get tests exercise).
func TestClientDoPutQuotedMetachar(t *testing.T) {
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "star*file"), []byte("S"), 0644)

	parts, _, _, _, err := makeargv(`put 'star*file'`, false)
	if err != nil {
		t.Fatalf("makeargv: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %v", parts)
	}
	if parts[1] != `star\*file` {
		t.Fatalf("expected escaped source %q, got %q", `star\*file`, parts[1])
	}

	ch := newMockChannel(makeResponseMsg(&Response{OK: true}))
	if err := doPut(ch, localDir, "/remote", parts, true, nil); err != nil {
		t.Fatalf("doPut error: %v", err)
	}

	var got Request
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "put" || got.Path != "/remote/star*file" {
		t.Fatalf("expected put /remote/star*file, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoPutNoMatch verifies that a put source with no matching local
// file falls back to the literal path and fails with the underlying error.
func TestClientDoPutNoMatch(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel()
	err := doPut(ch, localDir, "/remote", []string{"put", "zzz*.txt"}, true, nil)
	if err == nil {
		t.Fatal("expected error for non-matching put source")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestClientDoPutInvalidPattern verifies that a malformed put glob pattern is
// rejected up front.
func TestClientDoPutInvalidPattern(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel()
	err := doPut(ch, localDir, "/remote", []string{"put", "["}, true, nil)
	if err == nil {
		t.Fatal("expected error for invalid glob pattern")
	}
}

// TestClientDoPutRecursiveWildcard verifies that put -r with a glob source
// transfers matched directories recursively through uploadOne.
func TestClientDoPutRecursiveWildcard(t *testing.T) {
	localDir := t.TempDir()
	dirPath := filepath.Join(localDir, "d")
	os.MkdirAll(dirPath, 0o755)
	os.WriteFile(filepath.Join(dirPath, "f.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(localDir, "solo.txt"), []byte("solo"), 0644)

	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: false, Error: "no such file"}),                       // stat /remote/d
		makeResponseMsg(&Response{ID: 2, OK: true, Info: &FileInfo{Name: "remote", IsDir: true}}), // stat /remote
		makeResponseMsg(&Response{ID: 3, OK: true}),                                               // mkdir /remote/d
		makeResponseMsg(&Response{ID: 4, OK: true}),                                               // put /remote/d/f.txt
		makeResponseMsg(&Response{ID: 5, OK: true}),                                               // put /remote/solo.txt
	)

	if err := doPut(ch, localDir, "/remote", []string{"put", "-r", "*"}, true, nil); err != nil {
		t.Fatalf("doPut -r error: %v", err)
	}
	if len(ch.Writes) != 5 {
		t.Fatalf("expected 5 requests, got %d", len(ch.Writes))
	}
	var mkdirReq, putReq Request
	if err := decodeRequestFrame(ch.Writes[2], &mkdirReq); err != nil {
		t.Fatalf("unmarshal mkdir: %v", err)
	}
	if mkdirReq.Cmd != "mkdir" || mkdirReq.Path != "/remote/d" {
		t.Errorf("expected mkdir /remote/d, got %s %q", mkdirReq.Cmd, mkdirReq.Path)
	}
	if err := decodeRequestFrame(ch.Writes[4], &putReq); err != nil {
		t.Fatalf("unmarshal put: %v", err)
	}
	if putReq.Cmd != "put" || putReq.Path != "/remote/solo.txt" {
		t.Errorf("expected put /remote/solo.txt, got %s %q", putReq.Cmd, putReq.Path)
	}
}

// TestClientDoGetWildcardToLocalDir verifies that get with a glob source and an
// existing local directory destination downloads each match into that
// directory.
func TestClientDoGetWildcardToLocalDir(t *testing.T) {
	localDir := t.TempDir()
	destDir := filepath.Join(localDir, "dest")
	os.MkdirAll(destDir, 0o755)

	ch := newMockChannel(
		makeResponseMsg(&Response{OK: true, Entries: lsEntries("test", "testa", "nope")}),
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "test", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "testa", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("world")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote/path", []string{"get", "test*", "dest"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}

	// The ls request must target the source parent directory, not the
	// destination.
	var got Request
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote/path" {
		t.Fatalf("expected ls /remote/path, got %s %q", got.Cmd, got.Path)
	}

	for name, want := range map[string]string{"test": "hello", "testa": "world"} {
		content, err := os.ReadFile(filepath.Join(destDir, name))
		if err != nil {
			t.Fatalf("read %s from destination: %v", name, err)
		}
		if string(content) != want {
			t.Errorf("unexpected content for %s: %q", name, content)
		}
	}
	// Non-matching entries must not be downloaded anywhere.
	if _, err := os.Stat(filepath.Join(localDir, "nope")); !os.IsNotExist(err) {
		t.Errorf("expected no download for non-matching entry, stat err: %v", err)
	}
}

// TestClientDoGetWildcardToTrailingSlashDir verifies that get with a glob
// source and a slash-terminated destination treats the destination as a
// directory even when it does not exist yet, creating it for the download.
func TestClientDoGetWildcardToTrailingSlashDir(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(
		makeResponseMsg(&Response{OK: true, Entries: lsEntries("test")}),
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "test", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote/path", []string{"get", "test*", "newdir/"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(localDir, "newdir", "test"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}
}

// TestClientDoGetWildcardSingleToFile verifies that a get whose glob source
// matches a single entry and whose destination is not a directory uses the
// destination as the downloaded file name verbatim.
func TestClientDoGetWildcardSingleToFile(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(
		makeResponseMsg(&Response{OK: true, Entries: lsEntries("test")}),
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "test", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote/path", []string{"get", "test*", "out.txt"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(localDir, "out.txt"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}
}

// TestClientDoGetWildcardMultiToNonDir verifies that a get whose glob source
// matches multiple entries cannot target a file: the destination must be a
// directory.
func TestClientDoGetWildcardMultiToNonDir(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(makeResponseMsg(&Response{OK: true, Entries: lsEntries("test", "testa")}))

	err := doGet(ch, localDir, "/remote/path", []string{"get", "test*", "out.txt"}, true, nil)
	if err == nil {
		t.Fatal("expected error for multi-match get to non-directory")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestClientDoGetToExistingLocalDir verifies that a non-glob get to an
// existing local directory copies the remote file into it under its own
// basename.
func TestClientDoGetToExistingLocalDir(t *testing.T) {
	localDir := t.TempDir()
	destDir := filepath.Join(localDir, "dest")
	os.MkdirAll(destDir, 0o755)

	ch := newMockChannel(
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "remote.txt", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote", []string{"get", "remote.txt", "dest"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(destDir, "remote.txt"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}
}

// TestClientDoGetToNewLocalName verifies that a non-glob get to a target that
// is neither an existing directory nor slash-terminated uses the target as the
// local file name verbatim.
func TestClientDoGetToNewLocalName(t *testing.T) {
	localDir := t.TempDir()

	ch := newMockChannel(
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "remote.txt", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	newName := filepath.Join(localDir, "newname")
	if err := doGet(ch, localDir, "/remote", []string{"get", "remote.txt", "newname"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}

	content, err := os.ReadFile(newName)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}
}

// TestClientDoGetToAbsoluteTarget verifies that an absolute local destination
// is used as-is rather than being joined onto the local working directory.
func TestClientDoGetToAbsoluteTarget(t *testing.T) {
	localDir := t.TempDir()
	outDir := t.TempDir()
	target := filepath.Join(outDir, "absolute.txt")

	ch := newMockChannel(
		makeResponseMsg(&Response{OK: true, Info: &FileInfo{Name: "remote.txt", Size: 5}}),
		makeResponseMsg(&Response{OK: true, Data: []byte("hello")}),
		makeResponseMsg(&Response{OK: true, Data: []byte{}}),
	)

	if err := doGet(ch, localDir, "/remote", []string{"get", "remote.txt", target}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}
	if _, err := os.Stat(filepath.Join(localDir, "absolute.txt")); !os.IsNotExist(err) {
		t.Errorf("expected file not to be placed under localDir, stat err: %v", err)
	}
}

func TestResolveCDTarget(t *testing.T) {
	const (
		remoteDir = "/home/alice/work"
		homeDir   = "/home/alice"
		prevDir   = "/home/alice/projects"
	)

	tests := []struct {
		name       string
		arg        string
		hasPrevDir bool
		want       string
		wantOK     bool
	}{
		{name: "no argument goes to home", arg: "", want: homeDir, wantOK: true},
		{name: "tilde goes to home", arg: "~", want: homeDir, wantOK: true},
		{name: "tilde slash subdir", arg: "~/docs", want: homeDir + "/docs", wantOK: true},
		{name: "tilde slash nested", arg: "~/a/b/c", want: homeDir + "/a/b/c", wantOK: true},
		{name: "bare tilde slash", arg: "~/", want: homeDir, wantOK: true},
		{name: "dash goes to previous dir", arg: "-", hasPrevDir: true, want: prevDir, wantOK: true},
		{name: "dash without previous dir fails", arg: "-", wantOK: false},
		{name: "absolute path used as-is", arg: "/tmp", want: "/tmp", wantOK: true},
		{name: "relative path joined to remote dir", arg: "sub", want: remoteDir + "/sub", wantOK: true},
		{name: "relative dot", arg: ".", want: remoteDir, wantOK: true},
		{name: "relative parent", arg: "..", want: homeDir, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := resolveCDTarget(tt.arg, remoteDir, homeDir, prevDir, tt.hasPrevDir)
			if ok != tt.wantOK {
				t.Fatalf("resolveCDTarget(%q) ok = %v, want %v", tt.arg, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("resolveCDTarget(%q) = %q, want %q", tt.arg, got, tt.want)
			}
		})
	}
}

// --- Tilde expansion ---

func TestExpandTilde(t *testing.T) {
	const remoteHome = "/home/alice"
	const localHome = "/home/bob"

	// Remote paths are joined and cleaned with path.Join.
	remoteCases := []struct {
		in, want string
	}{
		{"~", remoteHome},
		{"~/", remoteHome},
		{"~/docs", remoteHome + "/docs"},
		{"~/a/b", remoteHome + "/a/b"},
		{"~/./x", remoteHome + "/x"},
		{"~/../x", "/home/x"}, // cleaned like a shell path
		{"~user", "~user"},    // ~other users are not expanded
		{"foo~", "foo~"},      // tilde not at the start is literal
		{"~/docs", remoteHome + "/docs"},
		{"sub/dir", "sub/dir"},
		{"", ""},
	}
	for _, c := range remoteCases {
		if got := expandTildePath(c.in, remoteHome); got != c.want {
			t.Errorf("expandTildePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// Local paths are joined and cleaned with filepath.Join.
	localCases := []struct {
		in, want string
	}{
		{"~", localHome},
		{"~/", localHome},
		{"~/docs", localHome + "/docs"},
		{"~/a/b", localHome + "/a/b"},
		{"~bob", "~bob"},
		{"foo~", "foo~"},
		{"", ""},
	}
	for _, c := range localCases {
		if got := expandLocalTilde(c.in, localHome); got != c.want {
			t.Errorf("expandLocalTilde(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// An unknown home leaves the path untouched, so the command fails with
	// the underlying error instead of silently pointing at an empty path.
	if got := expandTildePath("~/x", ""); got != "~/x" {
		t.Errorf("expandTildePath with empty home = %q, want %q", got, "~/x")
	}
	if got := expandLocalTilde("~", ""); got != "~" {
		t.Errorf("expandLocalTilde with empty home = %q, want %q", got, "~")
	}
}

func TestExpandCommandArgs(t *testing.T) {
	const remoteHome = "/home/alice"
	const localHome = "/home/bob"

	cases := []struct {
		name  string
		parts []string
		want  []string
	}{
		// Remote-only commands expand to the remote home.
		{name: "ls bare tilde", parts: []string{"ls", "~"}, want: []string{"ls", remoteHome}},
		{name: "ls tilde subdir", parts: []string{"ls", "~/docs"}, want: []string{"ls", remoteHome + "/docs"}},
		{name: "ls tilde glob", parts: []string{"ls", "~/te*"}, want: []string{"ls", remoteHome + "/te*"}},
		{name: "mkdir", parts: []string{"mkdir", "~/new"}, want: []string{"mkdir", remoteHome + "/new"}},
		{name: "rm", parts: []string{"rm", "~/f.txt"}, want: []string{"rm", remoteHome + "/f.txt"}},
		{name: "rmdir", parts: []string{"rmdir", "~/d"}, want: []string{"rmdir", remoteHome + "/d"}},
		// Relative paths and non-tilde arguments are left alone.
		{name: "ls relative", parts: []string{"ls", "docs"}, want: []string{"ls", "docs"}},
		{name: "ls absolute", parts: []string{"ls", "/etc"}, want: []string{"ls", "/etc"}},
		// Local commands expand to the local home.
		{name: "lcd", parts: []string{"lcd", "~"}, want: []string{"lcd", localHome}},
		{name: "lls", parts: []string{"lls", "~/pics"}, want: []string{"lls", localHome + "/pics"}},
		// get: source is remote, target is local.
		{name: "get remote source", parts: []string{"get", "~"}, want: []string{"get", remoteHome}},
		{name: "get local target", parts: []string{"get", "f", "~"}, want: []string{"get", "f", localHome}},
		{name: "get both", parts: []string{"get", "~/f", "~"}, want: []string{"get", remoteHome + "/f", localHome}},
		{name: "get -r flags", parts: []string{"get", "-r", "~/f", "~"}, want: []string{"get", "-r", remoteHome + "/f", localHome}},
		// put: source is local, target is remote.
		{name: "put local source", parts: []string{"put", "~"}, want: []string{"put", localHome}},
		{name: "put remote target", parts: []string{"put", "f", "~"}, want: []string{"put", "f", remoteHome}},
		{name: "put both", parts: []string{"put", "~/f", "~"}, want: []string{"put", localHome + "/f", remoteHome}},
		{name: "put --recursive", parts: []string{"put", "--recursive", "~/f", "~/d"},
			want: []string{"put", "--recursive", localHome + "/f", remoteHome + "/d"}},
		// cd resolves "~" itself and is left untouched here.
		{name: "cd untouched", parts: []string{"cd", "~"}, want: []string{"cd", "~"}},
		// Commands without path arguments are untouched.
		{name: "pwd", parts: []string{"pwd"}, want: []string{"pwd"}},
		{name: "lpwd", parts: []string{"lpwd"}, want: []string{"lpwd"}},
		{name: "help", parts: []string{"help"}, want: []string{"help"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parts := append([]string(nil), c.parts...)
			expandCommandArgs(parts, remoteHome, localHome)
			if len(parts) != len(c.want) {
				t.Fatalf("expandCommandArgs(%v) = %v, want %v", c.parts, parts, c.want)
			}
			for i := range parts {
				if parts[i] != c.want[i] {
					t.Fatalf("expandCommandArgs(%v) = %v, want %v", c.parts, parts, c.want)
				}
			}
		})
	}
}

func TestTransferArgIndices(t *testing.T) {
	if s, tg := transferArgIndices([]string{"get", "src"}); s != 1 || tg != 2 {
		t.Errorf("no target: source=%d target=%d, want 1 and 2", s, tg)
	}
	if s, tg := transferArgIndices([]string{"get", "src", "dst"}); s != 1 || tg != 2 {
		t.Errorf("with target: source=%d target=%d, want 1 and 2", s, tg)
	}
	if s, tg := transferArgIndices([]string{"get", "-r", "src", "dst"}); s != 2 || tg != 3 {
		t.Errorf("with -r: source=%d target=%d, want 2 and 3", s, tg)
	}
	if s, tg := transferArgIndices([]string{"put", "--recursive", "src"}); s != 2 || tg != 3 {
		t.Errorf("with --recursive: source=%d target=%d, want 2 and 3", s, tg)
	}
}

// TestClientDoLsTildeExpandedAbsolute pins that an ls argument whose tilde
// has been expanded at dispatch time (an absolute path) is sent to the server
// as-is rather than being joined onto the remote working directory.
func TestClientDoLsTildeExpandedAbsolute(t *testing.T) {
	ch := newMockChannel(makeResponseMsg(&Response{OK: true, Entries: lsEntries("notes.txt")}))
	// parts simulate the output of expandCommandArgs(["ls", "~"]) with a
	// remote home of /home/alice.
	if err := doLs(ch, "/remote", []string{"ls", "/home/alice"}); err != nil {
		t.Fatalf("doLs error: %v", err)
	}
	var got Request
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	if err := decodeRequestFrame(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/home/alice" {
		t.Fatalf("expected ls /home/alice, got %s %q", got.Cmd, got.Path)
	}
}
