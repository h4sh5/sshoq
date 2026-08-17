package sftp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
	"github.com/h4sh5/sshoq/util"
)

// --- Server-side symlink reporting ---

func TestServerStatSymlinkReportsTarget(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "real.txt"), []byte("hello"), 0644)
	if err := os.Symlink("real.txt", filepath.Join(tmp, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "stat", Path: "link.txt"})
	if !resp.OK {
		t.Fatalf("stat failed: %s", resp.Error)
	}
	if resp.Info == nil || !resp.Info.IsSymlink {
		t.Fatalf("expected symlink info, got %+v", resp.Info)
	}
	if resp.Info.LinkTarget != "real.txt" {
		t.Fatalf("expected link target real.txt, got %q", resp.Info.LinkTarget)
	}
	if resp.Info.IsDir {
		t.Fatalf("symlink must not be reported as a directory: %+v", resp.Info)
	}
	// The size is the link's own (lstat), not the target's.
	if resp.Info.Size != int64(len("real.txt")) {
		t.Fatalf("expected lstat size %d, got %d", len("real.txt"), resp.Info.Size)
	}
}

func TestServerStatRegularFileNotSymlink(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "real.txt"), []byte("hello"), 0644)

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "stat", Path: "real.txt"})
	if !resp.OK {
		t.Fatalf("stat failed: %s", resp.Error)
	}
	if resp.Info == nil || resp.Info.IsSymlink || resp.Info.LinkTarget != "" {
		t.Fatalf("unexpected symlink fields on regular file: %+v", resp.Info)
	}
}

func TestServerLsSymlinkReportsTarget(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "real.txt"), []byte("hello"), 0644)
	if err := os.Symlink("real.txt", filepath.Join(tmp, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	sess := &ServerSession{currentDir: tmp}
	resp := sess.handleRequest(Request{Cmd: "ls", Path: "."})
	if !resp.OK {
		t.Fatalf("ls failed: %s", resp.Error)
	}
	var link *FileInfo
	for i := range resp.Entries {
		if resp.Entries[i].Name == "link.txt" {
			link = &resp.Entries[i]
		}
	}
	if link == nil {
		t.Fatalf("symlink entry missing: %+v", resp.Entries)
	}
	if !link.IsSymlink || link.LinkTarget != "real.txt" {
		t.Fatalf("expected symlink entry with target real.txt, got %+v", link)
	}
	if link.IsDir {
		t.Fatalf("symlink must not be reported as a directory: %+v", link)
	}
}

func TestServerGetSymlinkNotFollowedServerSide(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "real.txt"), []byte("hello"), 0644)
	if err := os.Symlink("real.txt", filepath.Join(tmp, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	sess := &ServerSession{currentDir: tmp}
	// The server does not follow: it reports links via stat/ls and reads the
	// resolved path the client sends. A raw get on a symlink fails (ELOOP).
	resp := sess.handleRequest(Request{Cmd: "get", Path: "link.txt"})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected get of a symlink to fail server-side, got %+v", resp)
	}
	if len(resp.Data) != 0 {
		t.Fatalf("expected no data from a symlink get, got %q", resp.Data)
	}
}

// --- Client-side download: following server symlinks ---

func TestDownloadFileFollowsServerSymlink(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "out.txt")

	// stat link.txt -> symlink to real.txt; stat real.txt -> regular file.
	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "link.txt", IsSymlink: true, LinkTarget: "real.txt"}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Info: &FileInfo{Name: "real.txt", Size: 5}}),
		makeJSONDataMsg(&Response{ID: 3, OK: true, Data: []byte("hello")}),
		makeJSONDataMsg(&Response{ID: 4, OK: true, Data: []byte{}}),
	)

	if err := downloadFile(ch, "/remote/link.txt", localPath, true, nil); err != nil {
		t.Fatalf("downloadFile error: %v", err)
	}

	got, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("unexpected content: %q", got)
	}

	// The client must have asked the server for the resolved path, not the
	// link itself: the initial stat names the link, the get requests name the
	// resolved target so the server reads the regular file.
	if len(ch.Writes) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(ch.Writes))
	}
	var req Request
	if err := json.Unmarshal(ch.Writes[0], &req); err != nil {
		t.Fatalf("unmarshal stat: %v", err)
	}
	if req.Cmd != "stat" || req.Path != "/remote/link.txt" {
		t.Fatalf("expected stat /remote/link.txt, got %s %q", req.Cmd, req.Path)
	}
	if err := json.Unmarshal(ch.Writes[1], &req); err != nil {
		t.Fatalf("unmarshal stat: %v", err)
	}
	if req.Cmd != "stat" || req.Path != "/remote/real.txt" {
		t.Fatalf("expected stat /remote/real.txt, got %s %q", req.Cmd, req.Path)
	}
	if err := json.Unmarshal(ch.Writes[2], &req); err != nil {
		t.Fatalf("unmarshal get: %v", err)
	}
	if req.Cmd != "get" || req.Path != "/remote/real.txt" {
		t.Fatalf("expected get /remote/real.txt, got %s %q", req.Cmd, req.Path)
	}
}

func TestDownloadFileFollowsRelativeAndAbsoluteTargets(t *testing.T) {
	localPath := filepath.Join(t.TempDir(), "out.txt")

	// link -> ../other/real.txt (relative to the link's directory).
	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "link", IsSymlink: true, LinkTarget: "../other/real.txt"}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Info: &FileInfo{Name: "real.txt", Size: 4}}),
		makeJSONDataMsg(&Response{ID: 3, OK: true, Data: []byte("data")}),
		makeJSONDataMsg(&Response{ID: 4, OK: true, Data: []byte{}}),
	)
	if err := downloadFile(ch, "/home/u/sub/link", localPath, true, nil); err != nil {
		t.Fatalf("downloadFile (relative target) error: %v", err)
	}
	var req Request
	if err := json.Unmarshal(ch.Writes[1], &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Path != "/home/u/other/real.txt" {
		t.Fatalf("expected resolved relative target /home/u/other/real.txt, got %q", req.Path)
	}

	// link -> /etc/passwd (absolute target used verbatim).
	ch2 := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "link", IsSymlink: true, LinkTarget: "/etc/passwd"}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Info: &FileInfo{Name: "passwd", Size: 4}}),
		makeJSONDataMsg(&Response{ID: 3, OK: true, Data: []byte("data")}),
		makeJSONDataMsg(&Response{ID: 4, OK: true, Data: []byte{}}),
	)
	if err := downloadFile(ch2, "/home/u/link", localPath, true, nil); err != nil {
		t.Fatalf("downloadFile (absolute target) error: %v", err)
	}
	if err := json.Unmarshal(ch2.Writes[1], &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Path != "/etc/passwd" {
		t.Fatalf("expected absolute target /etc/passwd, got %q", req.Path)
	}
}

func TestDownloadFileNoFollowRejectsServerSymlink(t *testing.T) {
	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "link.txt", IsSymlink: true, LinkTarget: "real.txt"}}),
	)

	err := downloadFile(ch, "/remote/link.txt", filepath.Join(t.TempDir(), "out"), false, nil)
	if err == nil {
		t.Fatal("expected error for no-follow download of a symlink")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected 'symbolic link' error, got %v", err)
	}
	// Only the initial stat was sent: no follow, no transfer.
	if len(ch.Writes) != 1 {
		t.Fatalf("expected only the stat request, got %d", len(ch.Writes))
	}
}

func TestDownloadFileFollowSymlinkLoop(t *testing.T) {
	// link -> itself: the client must give up after the follow limit. The mock
	// returns the same symlink for each of the fatal-link resolution hops.
	var msgs []ssh3Messages.Message
	for i := 0; i < maxSymlinkFollow; i++ {
		msgs = append(msgs, makeJSONDataMsg(&Response{ID: uint64(i + 1), OK: true, Info: &FileInfo{Name: "loop", IsSymlink: true, LinkTarget: "loop"}}))
	}
	ch := newMockChannel(msgs...)
	err := downloadFile(ch, "/remote/loop", filepath.Join(t.TempDir(), "out"), true, nil)
	if err == nil {
		t.Fatal("expected error for symlink loop")
	}
	if !strings.Contains(err.Error(), "too many levels of symbolic links") {
		t.Fatalf("expected symlink loop error, got %v", err)
	}
}

func TestDownloadRecursiveFollowsServerSymlinkToDir(t *testing.T) {
	tmp := t.TempDir()
	localRoot := filepath.Join(tmp, "downloaded")

	// remote-dir/ contains a symlink "dirlink" -> "sub" (a directory).
	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote-dir", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 2, OK: true, Entries: []FileInfo{
			{Name: "file.txt", Size: 5, Mode: 0644},
			{Name: "dirlink", IsSymlink: true, LinkTarget: "sub"},
		}}),
		makeJSONDataMsg(&Response{ID: 3, OK: true, Data: []byte("hello")}),
		makeJSONDataMsg(&Response{ID: 4, OK: true, Data: []byte{}}),
		// Following dirlink: stat resolves sub, ls sub.
		makeJSONDataMsg(&Response{ID: 5, OK: true, Info: &FileInfo{Name: "sub", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 6, OK: true, Entries: []FileInfo{{Name: "nested.txt", Size: 11, Mode: 0644}}}),
		makeJSONDataMsg(&Response{ID: 7, OK: true, Data: []byte("hello world")}),
		makeJSONDataMsg(&Response{ID: 8, OK: true, Data: []byte{}}),
	)

	if err := downloadRecursive(ch, "remote-dir", localRoot, true, nil); err != nil {
		t.Fatalf("downloadRecursive error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(localRoot, "file.txt"))
	if err != nil {
		t.Fatalf("read file.txt: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("unexpected file.txt content: %q", got)
	}
	nested, err := os.ReadFile(filepath.Join(localRoot, "dirlink", "nested.txt"))
	if err != nil {
		t.Fatalf("read dirlink/nested.txt: %v", err)
	}
	if string(nested) != "hello world" {
		t.Fatalf("unexpected dirlink/nested.txt content: %q", nested)
	}
}

func TestDownloadRecursiveNoFollowRejectsServerSymlink(t *testing.T) {
	localRoot := filepath.Join(t.TempDir(), "downloaded")

	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote-dir", IsDir: true}}),
		// The symlink entry comes first so it is rejected before any file chunk
		// request is attempted.
		makeJSONDataMsg(&Response{ID: 2, OK: true, Entries: []FileInfo{
			{Name: "dirlink", IsSymlink: true, LinkTarget: "sub"},
			{Name: "file.txt", Size: 5, Mode: 0644},
		}}),
	)

	err := downloadRecursive(ch, "remote-dir", localRoot, false, nil)
	if err == nil {
		t.Fatal("expected error for no-follow recursive download of a symlink")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected 'symbolic link' error, got %v", err)
	}
}

// --- Client-side upload: following local symlinks ---

func TestUploadFileFollowsLocalSymlink(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "real.txt"), []byte("upload me"), 0644)
	if err := os.Symlink("real.txt", filepath.Join(tmp, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	ch := newMockChannel(makeJSONDataMsg(&Response{ID: 1, OK: true}))

	if err := uploadFile(ch, filepath.Join(tmp, "link.txt"), "/remote/link.txt", true, nil); err != nil {
		t.Fatalf("uploadFile error: %v", err)
	}
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	// The target's content must be uploaded, not the link itself.
	var req Request
	if err := json.Unmarshal(ch.Writes[0], &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(req.Data) != "upload me" {
		t.Fatalf("expected target content, got %q", req.Data)
	}
}

func TestUploadFileNoFollowRejectsLocalSymlink(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "real.txt"), []byte("upload me"), 0644)
	if err := os.Symlink("real.txt", filepath.Join(tmp, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	ch := newMockChannel()
	err := uploadFile(ch, filepath.Join(tmp, "link.txt"), "/remote/link.txt", false, nil)
	if err == nil {
		t.Fatal("expected error for no-follow upload of a symlink")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected 'symbolic link' error, got %v", err)
	}
	if len(ch.Writes) != 0 {
		t.Fatalf("expected no requests, got %d", len(ch.Writes))
	}
}

func TestUploadRecursiveFollowsLocalSymlinkToDir(t *testing.T) {
	tmp := t.TempDir()
	localRoot := filepath.Join(tmp, "src")
	os.MkdirAll(filepath.Join(localRoot, "sub"), 0o755)
	os.WriteFile(filepath.Join(localRoot, "file.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(localRoot, "sub", "nested.txt"), []byte("world"), 0644)
	if err := os.Symlink("sub", filepath.Join(localRoot, "dirlink")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// os.ReadDir returns entries sorted by name: dirlink, file.txt, sub.
	// Request sequence (follow=true):
	//   ensureRemoteDir("remote-dir"):
	//     stat("remote-dir") -> miss
	//     mkdir("remote-dir") -> ok
	//   recurse into dirlink: ensureRemoteDir("remote-dir/dirlink"):
	//     stat("remote-dir/dirlink") -> miss
	//     stat("remote-dir") -> dir
	//     mkdir("remote-dir/dirlink") -> ok
	//   upload nested.txt: put("remote-dir/dirlink/nested.txt") -> ok
	//   upload file.txt: put("remote-dir/file.txt") -> ok
	//   recurse into sub: ensureRemoteDir("remote-dir/sub"):
	//     stat("remote-dir/sub") -> miss
	//     stat("remote-dir") -> dir
	//     mkdir("remote-dir/sub") -> ok
	//   upload nested.txt: put("remote-dir/sub/nested.txt") -> ok
	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: false, Error: "no such file"}),
		makeJSONDataMsg(&Response{ID: 2, OK: true}),
		makeJSONDataMsg(&Response{ID: 3, OK: false, Error: "no such file"}),
		makeJSONDataMsg(&Response{ID: 4, OK: true, Info: &FileInfo{Name: "remote-dir", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 5, OK: true}),
		makeJSONDataMsg(&Response{ID: 6, OK: true}),
		makeJSONDataMsg(&Response{ID: 7, OK: true}),
		makeJSONDataMsg(&Response{ID: 8, OK: false, Error: "no such file"}),
		makeJSONDataMsg(&Response{ID: 9, OK: true, Info: &FileInfo{Name: "remote-dir", IsDir: true}}),
		makeJSONDataMsg(&Response{ID: 10, OK: true}),
		makeJSONDataMsg(&Response{ID: 11, OK: true}),
	)

	if err := uploadRecursive(ch, localRoot, "remote-dir", true, nil); err != nil {
		t.Fatalf("uploadRecursive error: %v", err)
	}
	if len(ch.Writes) != 11 {
		t.Fatalf("expected 11 requests, got %d: %v", len(ch.Writes), requestPaths(ch.Writes))
	}

	// The symlinked directory's file must be uploaded under dirlink/.
	var putReq Request
	found := false
	for _, w := range ch.Writes {
		if err := json.Unmarshal(w, &putReq); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if putReq.Cmd == "put" && putReq.Path == "remote-dir/dirlink/nested.txt" {
			found = true
			if string(putReq.Data) != "world" {
				t.Fatalf("expected nested content, got %q", putReq.Data)
			}
		}
	}
	if !found {
		t.Fatalf("expected put remote-dir/dirlink/nested.txt, requests: %v", requestPaths(ch.Writes))
	}
}

func TestUploadRecursiveNoFollowRejectsLocalSymlink(t *testing.T) {
	tmp := t.TempDir()
	localRoot := filepath.Join(tmp, "src")
	os.MkdirAll(localRoot, 0o755)
	os.WriteFile(filepath.Join(localRoot, "file.txt"), []byte("hello"), 0644)
	if err := os.Symlink("sub", filepath.Join(localRoot, "dirlink")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// The child "dirlink" is reached only after the remote root directory is
	// ensured (stat miss, then mkdir). With follow=false it is then rejected
	// as a symbolic link.
	ch := newMockChannel(
		makeJSONDataMsg(&Response{ID: 1, OK: false, Error: "no such file"}),
		makeJSONDataMsg(&Response{ID: 2, OK: true}),
	)
	err := uploadRecursive(ch, localRoot, "remote-dir", false, nil)
	if err == nil {
		t.Fatal("expected error for no-follow recursive upload of a symlink")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected 'symbolic link' error, got %v", err)
	}
}

// requestPaths decodes the requests recorded on a channel into their paths,
// for readable failure messages.
func requestPaths(writes [][]byte) []string {
	var out []string
	for _, w := range writes {
		var req Request
		if err := json.Unmarshal(w, &req); err != nil {
			out = append(out, "<unparseable>")
			continue
		}
		out = append(out, req.Cmd+":"+req.Path)
	}
	return out
}

// --- End-to-end: real server session against the client transfer functions ---

// pipeChannel is one end of an in-memory byte pipe pair that connects the SFTP
// client transfer functions to a live ServerSession in the same process:
// messages written to one end are delivered to the other end's NextMessage,
// mirroring the QUIC channel. It embeds *ssh3.MockChannel so the unexported
// interface methods (addDatagram, confirmChannel, ...) are promoted from a type
// in package ssh3 and the result satisfies ssh3.Channel; the exported routing
// methods are overridden to provide the live pipe. Writes are recorded for
// assertions.
type pipeChannel struct {
	*ssh3.MockChannel
	incoming chan ssh3Messages.Message
	peer     *pipeChannel
	closed   chan struct{}
	once     sync.Once

	mu     sync.Mutex
	writes [][]byte
}

func newPipePair() (*pipeChannel, *pipeChannel) {
	a := &pipeChannel{
		MockChannel: ssh3.NewMockChannel(),
		incoming:    make(chan ssh3Messages.Message, 64),
		closed:      make(chan struct{}),
	}
	b := &pipeChannel{
		MockChannel: ssh3.NewMockChannel(),
		incoming:    make(chan ssh3Messages.Message, 64),
		closed:      make(chan struct{}),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *pipeChannel) NextMessage() (ssh3Messages.Message, error) {
	select {
	case msg, ok := <-p.incoming:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-p.closed:
		return nil, io.EOF
	}
}

func (p *pipeChannel) WriteData(dataBuf []byte, dataType ssh3Messages.SSHDataType) (int, error) {
	if dataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
		return 0, fmt.Errorf("extended data not supported")
	}
	p.mu.Lock()
	p.writes = append(p.writes, append([]byte(nil), dataBuf...))
	p.mu.Unlock()
	msg := &ssh3Messages.DataOrExtendedDataMessage{DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE, Data: string(dataBuf)}
	select {
	case p.peer.incoming <- msg:
		return len(dataBuf), nil
	case <-p.peer.closed:
		return 0, io.EOF
	}
}

// Close signals the peer that no more messages will be sent in this
// direction, so its NextMessage returns EOF.
func (p *pipeChannel) Close() {
	p.MockChannel.Close()
	p.once.Do(func() { close(p.closed) })
}

func (p *pipeChannel) Writes() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]byte(nil), p.writes...)
}

func (p *pipeChannel) ChannelID() util.ChannelID           { return 0 }
func (p *pipeChannel) ConversationID() ssh3.ConversationID { return ssh3.ConversationID{} }
func (p *pipeChannel) ConversationStreamID() uint64        { return 0 }
func (p *pipeChannel) ReceiveDatagram(_ context.Context) ([]byte, error) {
	return nil, io.EOF
}
func (p *pipeChannel) SendDatagram(_ []byte) error                             { return fmt.Errorf("not supported") }
func (p *pipeChannel) SendRequest(_ *ssh3Messages.ChannelRequestMessage) error { return nil }
func (p *pipeChannel) CancelRead()                                             {}
func (p *pipeChannel) MaxPacketSize() uint64                                   { return 1 << 20 }
func (p *pipeChannel) ChannelType() string                                     { return "sftp" }
func (p *pipeChannel) WaitOpen() error                                         { return nil }
func (p *pipeChannel) RejectOpen(_ uint64, _ string) error                     { return fmt.Errorf("not supported") }
func (p *pipeChannel) confirmChannel(_ uint64) error                           { return nil }
func (p *pipeChannel) setDatagramSender(_ func([]byte) error)                  {}
func (p *pipeChannel) waitAddDatagram(_ context.Context, _ []byte) error       { return nil }
func (p *pipeChannel) addDatagram(datagram []byte) bool                        { return true }
func (p *pipeChannel) maybeSendHeader() error                                  { return nil }
func (p *pipeChannel) setDgramQueue(_ *util.DatagramsQueue)                    {}

// servePipe runs a real server session on serverEnd in the background,
// returning a function that closes the client end and waits for the server to
// exit.
func servePipe(t *testing.T, serverEnd *pipeChannel, remoteDir string) func() {
	t.Helper()
	done := make(chan struct{})
	go func() {
		serveChannelInProcess(context.Background(), currentTestUser(remoteDir), serverEnd)
		close(done)
	}()
	return func() {
		serverEnd.Close()
		<-done
	}
}

func TestEndToEndGetServerSymlink(t *testing.T) {
	remoteDir := t.TempDir()
	os.WriteFile(filepath.Join(remoteDir, "real.txt"), []byte("hello world"), 0644)
	if err := os.Symlink("real.txt", filepath.Join(remoteDir, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	localDir := t.TempDir()

	clientEnd, serverEnd := newPipePair()
	stop := servePipe(t, serverEnd, remoteDir)
	defer stop()

	// The client resolves the server-side link by asking the server for its
	// target, then reads the resolved file.
	if err := doGet(clientEnd, localDir, remoteDir, []string{"get", "link.txt"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(localDir, "link.txt"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("unexpected content: %q", got)
	}

	// The transfer must have read the resolved target, not the link.
	paths := requestPaths(clientEnd.Writes())
	if !containsPath(paths, "get:"+filepath.Join(remoteDir, "real.txt")) {
		t.Fatalf("expected a get of the resolved target, requests: %v", paths)
	}
}

func TestEndToEndGetServerSymlinkNoFollow(t *testing.T) {
	remoteDir := t.TempDir()
	os.WriteFile(filepath.Join(remoteDir, "real.txt"), []byte("hello world"), 0644)
	if err := os.Symlink("real.txt", filepath.Join(remoteDir, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	localDir := t.TempDir()

	clientEnd, serverEnd := newPipePair()
	stop := servePipe(t, serverEnd, remoteDir)
	defer stop()

	err := doGet(clientEnd, localDir, remoteDir, []string{"get", "link.txt"}, false, nil)
	if err == nil {
		t.Fatal("expected no-follow get of a symlink to fail")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected 'symbolic link' error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(localDir, "link.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("no file should have been downloaded, stat error: %v", statErr)
	}
}

func TestEndToEndGetRecursiveFollowsServerSymlink(t *testing.T) {
	remoteDir := t.TempDir()
	os.MkdirAll(filepath.Join(remoteDir, "rdir", "sub"), 0o755)
	os.WriteFile(filepath.Join(remoteDir, "rdir", "file.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(remoteDir, "rdir", "sub", "nested.txt"), []byte("world"), 0644)
	if err := os.Symlink("sub", filepath.Join(remoteDir, "rdir", "dirlink")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	localDir := t.TempDir()

	clientEnd, serverEnd := newPipePair()
	stop := servePipe(t, serverEnd, remoteDir)
	defer stop()

	if err := doGet(clientEnd, localDir, remoteDir, []string{"get", "-r", "rdir"}, true, nil); err != nil {
		t.Fatalf("doGet -r error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(localDir, "rdir", "file.txt"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("file.txt: content %q err %v", got, err)
	}
	nested, err := os.ReadFile(filepath.Join(localDir, "rdir", "dirlink", "nested.txt"))
	if err != nil || string(nested) != "world" {
		t.Fatalf("dirlink/nested.txt: content %q err %v", nested, err)
	}
}

func TestEndToEndPutClientSymlink(t *testing.T) {
	remoteDir := t.TempDir()
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "real.txt"), []byte("upload me"), 0644)
	if err := os.Symlink("real.txt", filepath.Join(localDir, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	clientEnd, serverEnd := newPipePair()
	stop := servePipe(t, serverEnd, remoteDir)
	defer stop()

	// The client follows the local link and uploads its target's content.
	if err := doPut(clientEnd, localDir, remoteDir, []string{"put", "link.txt"}, true, nil); err != nil {
		t.Fatalf("doPut error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(remoteDir, "link.txt"))
	if err != nil {
		t.Fatalf("read uploaded file: %v", err)
	}
	if string(got) != "upload me" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestEndToEndPutClientSymlinkNoFollow(t *testing.T) {
	remoteDir := t.TempDir()
	localDir := t.TempDir()
	os.WriteFile(filepath.Join(localDir, "real.txt"), []byte("upload me"), 0644)
	if err := os.Symlink("real.txt", filepath.Join(localDir, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	clientEnd, serverEnd := newPipePair()
	stop := servePipe(t, serverEnd, remoteDir)
	defer stop()

	err := doPut(clientEnd, localDir, remoteDir, []string{"put", "link.txt"}, false, nil)
	if err == nil {
		t.Fatal("expected no-follow put of a symlink to fail")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected 'symbolic link' error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(remoteDir, "link.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("no file should have been uploaded, stat error: %v", statErr)
	}
}

func TestEndToEndPutRecursiveFollowsClientSymlink(t *testing.T) {
	remoteDir := t.TempDir()
	localDir := t.TempDir()
	os.MkdirAll(filepath.Join(localDir, "ldir", "sub"), 0o755)
	os.WriteFile(filepath.Join(localDir, "ldir", "file.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(localDir, "ldir", "sub", "nested.txt"), []byte("world"), 0644)
	if err := os.Symlink("sub", filepath.Join(localDir, "ldir", "dirlink")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	clientEnd, serverEnd := newPipePair()
	stop := servePipe(t, serverEnd, remoteDir)
	defer stop()

	if err := doPut(clientEnd, localDir, remoteDir, []string{"put", "-r", "ldir"}, true, nil); err != nil {
		t.Fatalf("doPut -r error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(remoteDir, "ldir", "file.txt"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("file.txt: content %q err %v", got, err)
	}
	nested, err := os.ReadFile(filepath.Join(remoteDir, "ldir", "dirlink", "nested.txt"))
	if err != nil || string(nested) != "world" {
		t.Fatalf("dirlink/nested.txt: content %q err %v", nested, err)
	}
}

func TestEndToEndGetSymlinkToAbsolutePath(t *testing.T) {
	remoteDir := t.TempDir()
	target := filepath.Join(remoteDir, "elsewhere.txt")
	os.WriteFile(target, []byte("absolute"), 0644)
	if err := os.Symlink(target, filepath.Join(remoteDir, "abslink.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	localDir := t.TempDir()

	clientEnd, serverEnd := newPipePair()
	stop := servePipe(t, serverEnd, remoteDir)
	defer stop()

	if err := doGet(clientEnd, localDir, remoteDir, []string{"get", "abslink.txt"}, true, nil); err != nil {
		t.Fatalf("doGet error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(localDir, "abslink.txt"))
	if err != nil || string(got) != "absolute" {
		t.Fatalf("abslink.txt: content %q err %v", got, err)
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
