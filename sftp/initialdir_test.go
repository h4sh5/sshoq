package sftp

import (
	"strings"
	"testing"
)

// --- Initial remote directory (`sshoq -sftp host%/tmp`) ---

// TestResolveInitialRemoteDir checks how the remote directory requested on the
// command line is resolved against the home directory the server starts the
// session in: absolute paths are used as-is, "~" and "~/x" point into the home,
// and a relative path resolves against it, exactly like a `cd` issued from the
// remote home.
func TestResolveInitialRemoteDir(t *testing.T) {
	const homeDir = "/home/alice"

	tests := []struct {
		name       string
		initialDir string
		want       string
	}{
		{name: "empty starts in home", initialDir: "", want: homeDir},
		{name: "absolute path", initialDir: "/tmp", want: "/tmp"},
		{name: "root", initialDir: "/", want: "/"},
		{name: "tilde", initialDir: "~", want: homeDir},
		{name: "tilde slash subdir", initialDir: "~/docs", want: homeDir + "/docs"},
		{name: "relative path", initialDir: "projects", want: homeDir + "/projects"},
		{name: "relative nested path", initialDir: "projects/a/b", want: homeDir + "/projects/a/b"},
		{name: "relative parent", initialDir: "..", want: "/home"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveInitialRemoteDir(tt.initialDir, homeDir); got != tt.want {
				t.Errorf("resolveInitialRemoteDir(%q) = %q, want %q", tt.initialDir, got, tt.want)
			}
		})
	}
}

// TestChangeRemoteDir verifies that the change is requested for the resolved
// path and that the directory the server reports afterwards is the one
// returned, so the session works on the location the server settled on.
func TestChangeRemoteDir(t *testing.T) {
	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true}),
		makeResponseMsg(&Response{ID: 2, OK: true, Path: "/home/alice/docs"}),
	)

	got, err := changeRemoteDir(ch, "/home/alice/docs")
	if err != nil {
		t.Fatalf("changeRemoteDir error: %v", err)
	}
	if got != "/home/alice/docs" {
		t.Errorf("expected the directory reported by the server, got %q", got)
	}

	// a cd request followed by the pwd that confirms where the session is
	if len(ch.Writes) != 2 {
		t.Fatalf("expected 2 written requests, got %d", len(ch.Writes))
	}
	var cdReq, pwdReq Request
	if err := decodeRequestFrame(ch.Writes[0], &cdReq); err != nil {
		t.Fatalf("unmarshal written cd request: %v", err)
	}
	if cdReq.Cmd != "cd" || cdReq.Path != "/home/alice/docs" {
		t.Errorf("unexpected written cd request: %+v", cdReq)
	}
	if err := decodeRequestFrame(ch.Writes[1], &pwdReq); err != nil {
		t.Fatalf("unmarshal written pwd request: %v", err)
	}
	if pwdReq.Cmd != "pwd" {
		t.Errorf("expected a pwd request after the change, got: %+v", pwdReq)
	}
}

// TestChangeRemoteDirFallsBackToTarget covers a server that answers the pwd
// following the change with an error: the requested path is then reported.
func TestChangeRemoteDirFallsBackToTarget(t *testing.T) {
	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: true}),
		makeResponseMsg(&Response{ID: 2, OK: false, Error: "pwd unsupported"}),
	)

	got, err := changeRemoteDir(ch, "/tmp")
	if err != nil {
		t.Fatalf("changeRemoteDir error: %v", err)
	}
	if got != "/tmp" {
		t.Errorf("expected the requested target /tmp, got %q", got)
	}
}

// TestChangeRemoteDirServerError checks that a refused change (missing
// directory, no permission) is reported as an error naming the directory, so
// `sshoq -sftp host%/missing` fails instead of silently staying in the home.
func TestChangeRemoteDirServerError(t *testing.T) {
	ch := newMockChannel(
		makeResponseMsg(&Response{ID: 1, OK: false, Error: "no such file or directory"}),
	)

	got, err := changeRemoteDir(ch, "/tmp/missing")
	if err == nil {
		t.Fatalf("expected an error for a refused cd, got directory %q", got)
	}
	if !strings.Contains(err.Error(), "/tmp/missing") {
		t.Errorf("expected the error to name the directory, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("expected the server message in the error, got: %v", err)
	}
	// no pwd request is sent when the change itself fails
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 written request, got %d", len(ch.Writes))
	}
	if got != "" {
		t.Errorf("expected no directory on failure, got %q", got)
	}
}
