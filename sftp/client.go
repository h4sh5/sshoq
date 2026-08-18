package sftp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	ssh3 "github.com/h4sh5/sshoq"
	"github.com/h4sh5/sshoq/client"
)

func RunInteractiveClient(c *client.Client, follow bool) error {
	channel, err := c.OpenChannel("sftp", 30000, 0)
	if err != nil {
		return fmt.Errorf("could not open sftp channel: %w", err)
	}
	defer channel.Close()
	if err := channel.WaitOpen(); err != nil {
		return fmt.Errorf("could not open sftp channel: %w", err)
	}

	localDir, _ := os.Getwd()
	// The local user's home directory, for tilde expansion of local paths
	// (lcd, lls, the get target and put source).
	localHome, _ := os.UserHomeDir()
	if localHome != "" && !filepath.IsAbs(localHome) {
		if abs, err := filepath.Abs(localHome); err == nil {
			localHome = abs
		}
	}
	remoteDir := "."
	// The server starts every SFTP session in the authenticated user's home
	// directory, so the first pwd reveals it. It backs the `cd`/`cd ~` →
	// $HOME behavior, like OpenSSH sftp's bare `cd`.
	homeDir := remoteDir
	if pwdResp, err := doRequest(channel, &Request{Cmd: "pwd"}); err == nil && pwdResp.OK {
		remoteDir = pwdResp.Path
		homeDir = pwdResp.Path
	}
	// The previous remote directory, for `cd -`.
	prevDir := ""
	hasPrevDir := false

	input, err := newInteractiveReader()
	if err != nil {
		return err
	}
	defer input.close()
	if input.editor != nil {
		input.editor.completer = newCompleter(channel, &localDir, &remoteDir, homeDir, localHome)
	}

	for {
		line, err := input.readLine("sftp> ")
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		// Split the line into arguments with OpenSSH sftp quoting: single and
		// double quotes protect whitespace and metacharacters, backslash
		// escapes the next character, and '#' starts a comment. Glob
		// metacharacters keep their escaping for commands that glob; commands
		// that do not glob un-escape their paths via undoGlobEscape/unescape
		// when they consume them.
		parts, _, _, _, err := makeargv(line, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			continue
		}
		if len(parts) == 0 {
			continue
		}

		cmd := strings.ToLower(parts[0])

		// Expand a leading "~" or "~/" in path arguments to the appropriate
		// home directory before dispatching: the remote user's home for remote
		// arguments, the local user's home for local ones.
		expandCommandArgs(parts, homeDir, localHome)

		switch cmd {
		case "exit", "quit":
			return nil

		case "lcd":
			if len(parts) < 2 {
				fmt.Println("usage: lcd <local-path>")
				continue
			}
			if err := os.Chdir(undoGlobEscape(parts[1])); err != nil {
				fmt.Fprintf(os.Stderr, "lcd: %s\n", err)
			} else {
				localDir, _ = os.Getwd()
			}

		case "lls":
			target := localDir
			if len(parts) > 1 {
				target = resolveLocalPath(localDir, undoGlobEscape(parts[1]))
			}
			entries, err := os.ReadDir(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "lls: %s\n", err)
				continue
			}
			for _, e := range entries {
				info, _ := e.Info()
				printEntry(e.Name(), info)
			}

		case "lpwd":
			fmt.Println(localDir)

		case "cd":
			arg := ""
			if len(parts) > 1 {
				arg = undoGlobEscape(parts[1])
			}
			target, ok := resolveCDTarget(arg, remoteDir, homeDir, prevDir, hasPrevDir)
			if !ok {
				fmt.Fprintln(os.Stderr, "cd: no previous directory")
				continue
			}
			resp, err := doRequest(channel, &Request{Cmd: "cd", Path: target})
			if err != nil {
				fmt.Fprintf(os.Stderr, "cd: %s\n", err)
				continue
			}
			if !resp.OK {
				fmt.Fprintf(os.Stderr, "cd: %s\n", resp.Error)
			} else {
				prevDir, hasPrevDir = remoteDir, true
				pwdResp, _ := doRequest(channel, &Request{Cmd: "pwd"})
				if pwdResp != nil && pwdResp.OK {
					remoteDir = pwdResp.Path
				} else {
					remoteDir = target
				}
			}

		case "pwd":
			resp, err := doRequest(channel, &Request{Cmd: "pwd"})
			if err != nil {
				fmt.Fprintf(os.Stderr, "pwd: %s\n", err)
				continue
			}
			if resp.OK {
				fmt.Println(resp.Path)
			}

		case "ls":
			if err := doLs(channel, remoteDir, parts); err != nil {
				fmt.Fprintf(os.Stderr, "ls: %s\n", err)
				continue
			}

		case "get":
			cancel := &transferCancel{}
			err := input.runTransfer(cancel, func() error {
				return doGet(channel, localDir, remoteDir, parts, follow, cancel)
			})
			if err != nil {
				if errors.Is(err, ErrCancelled) {
					fmt.Println("Cancelled")
				} else {
					fmt.Fprintf(os.Stderr, "get: %s\n", err)
				}
				continue
			}

		case "put":
			cancel := &transferCancel{}
			err := input.runTransfer(cancel, func() error {
				return doPut(channel, localDir, remoteDir, parts, follow, cancel)
			})
			if err != nil {
				if errors.Is(err, ErrCancelled) {
					fmt.Println("Cancelled")
				} else {
					fmt.Fprintf(os.Stderr, "put: %s\n", err)
				}
			}

		case "mkdir":
			if len(parts) < 2 {
				fmt.Println("usage: mkdir <remote-path>")
				continue
			}
			target := undoGlobEscape(parts[1])
			if !path.IsAbs(target) {
				target = path.Join(remoteDir, target)
			}
			resp, err := doRequest(channel, &Request{Cmd: "mkdir", Path: target})
			if err != nil {
				fmt.Fprintf(os.Stderr, "mkdir: %s\n", err)
				continue
			}
			if !resp.OK {
				fmt.Fprintf(os.Stderr, "mkdir: %s\n", resp.Error)
			}

		case "rm":
			if len(parts) < 2 {
				fmt.Println("usage: rm <remote-file>")
				continue
			}
			// rm is a glob command in OpenSSH; this client removes a single
			// literal path, so the escaping is fully undone.
			target := unescape(parts[1])
			if !path.IsAbs(target) {
				target = path.Join(remoteDir, target)
			}
			resp, err := doRequest(channel, &Request{Cmd: "rm", Path: target})
			if err != nil {
				fmt.Fprintf(os.Stderr, "rm: %s\n", err)
				continue
			}
			if !resp.OK {
				fmt.Fprintf(os.Stderr, "rm: %s\n", resp.Error)
			}

		case "rmdir":
			if len(parts) < 2 {
				fmt.Println("usage: rmdir <remote-dir>")
				continue
			}
			target := undoGlobEscape(parts[1])
			if !path.IsAbs(target) {
				target = path.Join(remoteDir, target)
			}
			resp, err := doRequest(channel, &Request{Cmd: "rmdir", Path: target})
			if err != nil {
				fmt.Fprintf(os.Stderr, "rmdir: %s\n", err)
				continue
			}
			if !resp.OK {
				fmt.Fprintf(os.Stderr, "rmdir: %s\n", resp.Error)
			}

		case "help":
			printHelp()

		default:
			fmt.Printf("Unknown command: %s\n", cmd)
			printHelp()
		}
	}

	return nil
}

// resolveCDTarget computes the remote path a `cd` command should change to,
// mirroring OpenSSH sftp and shell cd semantics:
//   - no argument, "~" or "~/..." resolve to the user's home directory;
//   - "-" resolves to the previous directory (ok is false when there is none);
//   - absolute paths are used as-is;
//   - any other path is resolved against the current remote directory.
func resolveCDTarget(arg, remoteDir, homeDir, prevDir string, hasPrevDir bool) (target string, ok bool) {
	switch {
	case arg == "" || arg == "~":
		return homeDir, true
	case strings.HasPrefix(arg, "~/"):
		return path.Join(homeDir, arg[2:]), true
	case arg == "-":
		if !hasPrevDir {
			return "", false
		}
		return prevDir, true
	case path.IsAbs(arg):
		return arg, true
	default:
		return path.Join(remoteDir, arg), true
	}
}

// expandCommandArgs applies tilde expansion to the argument list of an SFTP
// command line, replacing a leading "~" or "~/" in each path argument with
// the appropriate home directory: the remote user's home for remote arguments
// (ls, mkdir, rm, rmdir, the get source and put target) and the local user's
// home for local arguments (lcd, lls, the get target and put source). The cd
// command resolves "~" itself via resolveCDTarget and is left untouched.
// parts is the argument list produced by makeargv and is mutated in place.
func expandCommandArgs(parts []string, remoteHome, localHome string) {
	cmd := strings.ToLower(parts[0])
	expand := func(i int, home string, join func(...string) string) {
		if i >= len(parts) {
			return
		}
		parts[i] = expandTilde(parts[i], home, join)
	}
	switch cmd {
	case "lcd", "lls":
		expand(1, localHome, filepath.Join)
	case "ls", "mkdir", "rm", "rmdir":
		expand(1, remoteHome, path.Join)
	case "get":
		source, target := transferArgIndices(parts)
		expand(source, remoteHome, path.Join)
		expand(target, localHome, filepath.Join)
	case "put":
		source, target := transferArgIndices(parts)
		expand(source, localHome, filepath.Join)
		expand(target, remoteHome, path.Join)
	}
}

// transferArgIndices returns the indexes of the source and target arguments
// of a get/put command line, skipping flag arguments such as -r.
func transferArgIndices(parts []string) (source, target int) {
	source = 1
	for source < len(parts) && strings.HasPrefix(parts[source], "-") {
		source++
	}
	return source, source + 1
}

// expandTildePath expands a leading "~" or "~/" in a remote path to the
// remote user's home directory.
func expandTildePath(p, home string) string {
	return expandTilde(p, home, path.Join)
}

// expandLocalTilde expands a leading "~" or "~/" in a local path to the
// local user's home directory.
func expandLocalTilde(p, home string) string {
	return expandTilde(p, home, filepath.Join)
}

// expandTilde expands a leading "~" or "~/" in p to home, mirroring shell
// tilde expansion for the current user: "~" alone becomes home itself and
// "~/x" becomes home/x. A tilde elsewhere in the path, or one followed by a
// character other than "/" (e.g. "~other"), is left unchanged. join cleans
// the joined path (path.Join for remote paths, filepath.Join for local ones),
// so "~/" with nothing after it yields home. When home is unknown ("") the
// path is left unchanged so the command fails with the underlying error
// instead of silently pointing at an empty path.
func expandTilde(p, home string, join func(...string) string) string {
	if home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return join(home, p[2:])
	}
	return p
}

// newCompleter builds the tab-completion callback for the interactive SFTP
// shell. It completes remote paths (resolved against *remoteDir, listed over
// the sftp channel) for commands that operate on the remote filesystem, and
// local paths (resolved against *localDir) for lcd/lls; for get and put the
// source argument is completed on the source side and the target argument on
// the target side. Candidates are full replacements for the word being edited,
// with directories ending in "/".
func newCompleter(channel ssh3.Channel, localDir, remoteDir *string, homeDir, localHome string) completeFunc {
	listRemote := func(dir string) ([]string, error) {
		dir = expandTildePath(dir, homeDir)
		if dir == "." {
			dir = *remoteDir
		} else if dir != "/" && !path.IsAbs(dir) {
			dir = path.Join(*remoteDir, dir)
		}
		resp, err := doRequest(channel, &Request{Cmd: "ls", Path: dir})
		if err != nil {
			return nil, err
		}
		if !resp.OK {
			return nil, serverError(dir, resp.Error)
		}
		names := make([]string, 0, len(resp.Entries))
		for _, e := range resp.Entries {
			if e.IsDir {
				names = append(names, e.Name+"/")
			} else {
				names = append(names, e.Name)
			}
		}
		return names, nil
	}

	listLocal := func(dir string) ([]string, error) {
		dir = expandLocalTilde(dir, localHome)
		if dir == "." {
			dir = *localDir
		} else if !filepath.IsAbs(dir) {
			dir = filepath.Join(*localDir, dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				names = append(names, e.Name()+"/")
			} else {
				names = append(names, e.Name())
			}
		}
		return names, nil
	}

	return func(buf []rune, pos int) ([]string, int) {
		// Parse the line up to the cursor with the OpenSSH quoting rules in
		// sloppy mode, so an unterminated quote (the user is mid-argument) is
		// tolerated. The last argument is the one being completed.
		prefix := string(buf[:pos])
		args, spans, quote, terminated, _ := makeargv(prefix, true)
		if len(args) == 0 {
			return nil, 0
		}

		// When the cursor sits on whitespace the word being completed is the
		// (empty) next argument at the cursor; otherwise it is the argument
		// containing the cursor, replaced from where that argument begins
		// (including its opening quote, if any) to the cursor. The spans are
		// byte offsets into prefix, so they are converted to rune indices
		// into buf.
		runeAt := func(b int) int {
			if b <= 0 {
				return 0
			}
			return utf8.RuneCountInString(prefix[:b])
		}
		start := pos
		parsedWord := ""
		if pos > 0 && !unicode.IsSpace(buf[pos-1]) {
			start = runeAt(spans[len(spans)-1][0])
			parsedWord = args[len(args)-1]
			if len(args) == 1 {
				return nil, 0 // the cursor is on the command word itself
			}
		}

		cmd := strings.ToLower(args[0])

		// The argument ordinal occupied by the word (1 = first argument),
		// skipping flag arguments such as -r/--recursive. When the cursor is
		// at an argument boundary the word is the next (empty) argument.
		argIdx := 1
		for _, a := range args[1:] {
			if a == parsedWord {
				break
			}
			if !strings.HasPrefix(a, "-") {
				argIdx++
			}
		}
		if strings.HasPrefix(parsedWord, "-") {
			return nil, start
		}

		local := false
		switch cmd {
		case "lcd", "lls":
			local = true
		case "get":
			local = argIdx == 2 // the target is local
		case "put":
			local = argIdx == 1 // the source is local
		case "cd", "ls", "mkdir", "rm", "rmdir":
			local = false
		default:
			return nil, start
		}

		listDir := listRemote
		if local {
			listDir = listLocal
		}
		candidates := completePath(unescape(parsedWord), listDir)

		// Render the candidates in the typed form, escaping the characters
		// that are special to the command line. When the completed word sits
		// inside quotes (an open quote at the cursor, or a word that already
		// starts with one), the candidate is re-quoted: only the quote
		// character itself needs escaping inside the quotes, and the quote is
		// closed when the user's was still open.
		quoted := quote != 0 && !terminated
		var q byte
		if quoted {
			q = quote
		} else if start < pos && (buf[start] == '\'' || buf[start] == '"') {
			quoted = true
			q = byte(buf[start])
		}
		for i, c := range candidates {
			if quoted {
				candidates[i] = string(q) + escapePath(c, q) + string(q)
			} else {
				candidates[i] = escapePath(c, 0)
			}
		}
		return candidates, start
	}
}

// completePath returns candidate completions for word by listing the directory
// it refers to and matching the entries against the word's final component.
// listDir returns the names of the entries of dir, with a trailing "/" on
// directories. Candidates are full replacements for word, so the caller can
// substitute them directly into the line. It returns nil when the directory
// cannot be listed.
func completePath(word string, listDir func(dir string) ([]string, error)) []string {
	dir := "."
	prefix := word
	base := "" // the word up to and including its last "/"
	if word == "~" {
		// A bare tilde: list the home directory and render its entries with
		// the "~/" prefix the user typed, so the completed line expands to
		// the same path. The listDir closure expands "~" to the actual home
		// directory for the side being completed.
		dir = "~"
		base = "~/"
		prefix = ""
	} else if i := strings.LastIndex(word, "/"); i >= 0 {
		base = word[:i+1]
		dir = word[:i]
		if dir == "" {
			dir = "/"
		}
		if strings.HasSuffix(word, "/") {
			prefix = "" // list the directory itself
		} else {
			prefix = word[i+1:]
		}
	}

	entries, err := listDir(dir)
	if err != nil {
		return nil
	}

	var candidates []string
	for _, name := range entries {
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		candidates = append(candidates, base+name)
	}
	return candidates
}

func doLs(channel ssh3.Channel, remoteDir string, parts []string) error {
	arg := ""
	if len(parts) > 1 {
		arg = parts[1]
	}

	// Split a possibly-globbed argument into the directory to list and a
	// pattern to filter its entries. Glob metacharacters (*, ?, [range]) only
	// apply to the final path component, matching shell glob semantics; "*" does
	// not cross a "/". When arg has no metacharacters we fall back to listing
	// the path directly, preserving the previous behavior.
	listDir := arg
	pattern := ""
	if dir, pat, ok := globSplit(arg); ok {
		listDir = dir
		pattern = pat
	}
	// The directory (whether globbed or not) is a literal path: remove the
	// escaping makeargv preserved for glob matching.
	listDir = unescape(listDir)

	// Resolve the directory relative to the remote working directory, mirroring
	// the handling of a non-glob "ls <path>".
	if pattern != "" || listDir != "" {
		if listDir == "" {
			listDir = remoteDir
		} else if !path.IsAbs(listDir) {
			listDir = path.Join(remoteDir, listDir)
		}
	} else {
		listDir = remoteDir
	}

	resp, err := doRequest(channel, &Request{Cmd: "ls", Path: listDir})
	if err != nil {
		return err
	}
	if !resp.OK {
		return serverError(listDir, resp.Error)
	}

	entries := resp.Entries
	if pattern != "" {
		var matched []FileInfo
		for _, e := range entries {
			ok, err := path.Match(pattern, e.Name)
			if err != nil {
				return fmt.Errorf("invalid pattern \"%s\": %w", pattern, err)
			}
			if ok {
				matched = append(matched, e)
			}
		}
		entries = matched
	}

	for _, e := range entries {
		printEntry(e.Name, sftpFileInfoFromEntry(e))
	}
	return nil
}

// runTransfer runs fn while making Ctrl+C cancel it. In terminal mode the
// session's terminal is raw, so Ctrl+C arrives as byte 0x03 on stdin instead
// of as SIGINT: a watcher goroutine consumes it (buffering any other typed
// bytes for the next prompt) and sets cancel, which fn's transfer loops check
// between chunks. With piped input the terminal is not raw, so Ctrl+C is
// delivered as a signal and a signal handler cancels instead.
func (r *interactiveReader) runTransfer(cancel *transferCancel, fn func() error) error {
	if r.editor == nil {
		stop := watchSignals(cancel)
		defer stop()
		return fn()
	}
	ctx, stop := context.WithCancel(context.Background())
	r.watchWg.Add(1)
	go r.watchCancel(ctx, cancel)
	err := fn()
	stop()
	r.watchWg.Wait()
	return err
}

// doGet downloads a remote file or directory, or every entry in the resolved
// source directory whose name matches a glob pattern. It mirrors doLs: when the
// remote source contains glob metacharacters in its final path component (*, ?,
// [range]) the source is split into the directory to list and a pattern to
// filter its entries via globSplit, and each matching entry is downloaded. An
// un-globbed source is downloaded directly, preserving the previous behavior.
// The -r flag is honored in both cases: directories (whether matched by the
// pattern or named directly) are transferred recursively via downloadOne.
func doGet(channel ssh3.Channel, localDir, remoteDir string, parts []string, follow bool, cancel *transferCancel) error {
	recursive, remoteSource, localTarget, err := parseTransferArgs(parts, "get")
	if err != nil {
		return err
	}

	// Split a possibly-globbed source into the directory to list and a pattern
	// to filter its entries. Glob metacharacters (*, ?, [range]) only apply to
	// the final path component, matching shell glob semantics; "*" does not
	// cross a "/". When the source has no metacharacters we fall back to
	// downloading it directly, preserving the previous behavior.
	sourceDir := remoteSource
	pattern := ""
	if dir, pat, ok := globSplit(remoteSource); ok {
		sourceDir = dir
		pattern = pat
	}
	// The directory (whether globbed or not) is a literal path: remove the
	// escaping makeargv preserved for glob matching.
	sourceDir = unescape(sourceDir)

	// Resolve the source relative to the remote working directory, mirroring the
	// handling of a non-glob "get <path>".
	if pattern != "" || sourceDir != "" {
		if sourceDir == "" {
			sourceDir = remoteDir
		} else if !path.IsAbs(sourceDir) {
			sourceDir = path.Join(remoteDir, sourceDir)
		}
	} else {
		sourceDir = remoteDir
	}

	if pattern != "" {
		// Glob: list the parent directory and download each entry whose name
		// matches the pattern.
		resp, err := doRequest(channel, &Request{Cmd: "ls", Path: sourceDir})
		if err != nil {
			return err
		}
		if !resp.OK {
			return serverError(sourceDir, resp.Error)
		}
		var matched []FileInfo
		for _, e := range resp.Entries {
			ok, err := path.Match(pattern, e.Name)
			if err != nil {
				return fmt.Errorf("invalid pattern \"%s\": %w", pattern, err)
			}
			if ok {
				matched = append(matched, e)
			}
		}

		// The local destination is a literal path (not globbed): remove the
		// escaping makeargv preserved for glob matching and resolve it against
		// the local working directory. A trailing separator marks the
		// destination as a directory even when it does not exist yet;
		// otherwise an existing local directory is detected with a stat.
		destDir := localDir
		destIsDir := true
		if target := undoGlobEscape(localTarget); target != "" {
			destDir = resolveLocalPath(localDir, target)
			destIsDir = false
			if strings.HasSuffix(target, string(filepath.Separator)) {
				destIsDir = true
			} else if info, err := os.Stat(destDir); err == nil && info.IsDir() {
				destIsDir = true
			}
		}

		// A single match may target a file name; multiple matches require a
		// directory destination (or none, in which case the files are placed
		// in the local working directory).
		if len(matched) > 1 && !destIsDir {
			return fmt.Errorf("cannot download %d files to %s: not a directory", len(matched), destDir)
		}

		for _, e := range matched {
			remoteFile := path.Join(sourceDir, e.Name)
			localFile := filepath.Join(destDir, e.Name)
			if len(matched) == 1 && !destIsDir {
				// A single match may target a file name directly.
				localFile = destDir
			}
			if err := downloadOne(channel, remoteFile, localFile, recursive, follow, cancel); err != nil {
				// With -r a permission-denied match is reported and skipped so
				// the remaining matches are still transferred.
				if recursive && isPermissionError(err) {
					fmt.Fprintf(os.Stderr, "get: %s\n", err)
					continue
				}
				return err
			}
		}
		return nil
	}

	// No glob: preserve the previous single-target behavior, but still resolve
	// a destination that names an existing local directory (or ends with a
	// path separator) by copying the file into it under its own basename,
	// mirroring the scp/download semantics.
	remoteFile := sourceDir
	// The local target is not globbed: undo the escaping of glob
	// metacharacters, mirroring OpenSSH's undo_glob_escape for get targets.
	localFile := undoGlobEscape(localTarget)
	base := filepath.Base(filepath.Clean(remoteFile))
	switch {
	case localFile == "":
		localFile = base
	case strings.HasSuffix(localFile, string(filepath.Separator)):
		localFile = filepath.Join(localFile, base)
	default:
		if info, err := os.Stat(resolveLocalPath(localDir, localFile)); err == nil && info.IsDir() {
			localFile = filepath.Join(localFile, base)
		}
	}
	localFile = resolveLocalPath(localDir, localFile)
	return downloadOne(channel, remoteFile, localFile, recursive, follow, cancel)
}

// downloadOne downloads remoteFile to localFile, descending into directories when
// recursive is set. It reproduces the transfer behavior of a non-glob "get" and
// is shared by the glob and non-glob paths of doGet so that wildcards work the
// same way with and without -r.
func downloadOne(channel ssh3.Channel, remoteFile, localFile string, recursive, follow bool, cancel *transferCancel) error {
	if recursive {
		return downloadRecursive(channel, remoteFile, localFile, follow, cancel)
	}
	return downloadFile(channel, remoteFile, localFile, follow, cancel)
}

// doPut uploads a local file or directory, or every local file matching a
// glob pattern in the source, to the remote filesystem. The source is
// expanded against the local filesystem with filepath.Glob, which understands
// the backslash escaping that makeargv preserves for glob metacharacters, so
// escaped metacharacters are matched literally. When the pattern matches
// nothing it is used as a literal path (mirroring OpenSSH's GLOB_NOCHECK), so
// the transfer fails with the underlying "no such file" error. The -r flag
// is honored in both cases: directories (whether matched by the pattern or
// named directly) are transferred recursively via uploadOne. The remote
// target is a literal path (not globbed): a single source may target a file
// name or a directory, while multiple sources require an existing directory
// (or no target, in which case each source is uploaded under its own
// basename).
func doPut(channel ssh3.Channel, localDir, remoteDir string, parts []string, follow bool, cancel *transferCancel) error {
	recursive, localSource, remoteTarget, err := parseTransferArgs(parts, "put")
	if err != nil {
		return err
	}

	// Expand a possibly-globbed source against the local filesystem. The
	// pattern is resolved against the local working directory (the process
	// working directory tracks it via lcd, but this keeps the source
	// independent of the process CWD). filepath.Glob understands the backslash
	// escaping that makeargv preserves for glob metacharacters, so escaped
	// metacharacters are matched literally.
	globSource := localSource
	if !filepath.IsAbs(globSource) {
		globSource = filepath.Join(localDir, localSource)
	}
	matches, globErr := filepath.Glob(globSource)
	if globErr != nil {
		return fmt.Errorf("invalid pattern \"%s\": %w", localSource, globErr)
	}
	if len(matches) == 0 {
		// No matches: fall back to the literal path so the transfer fails with
		// the underlying "no such file" error, mirroring OpenSSH's GLOB_NOCHECK
		// behavior.
		matches = []string{unescape(localSource)}
	}

	// The remote target is a literal path (not globbed): remove the escaping
	// makeargv preserved for glob matching, then resolve it against the remote
	// working directory for the directory check.
	remoteTarget = undoGlobEscape(remoteTarget)
	resolvedTarget := remoteTarget
	if resolvedTarget != "" && !path.IsAbs(resolvedTarget) {
		resolvedTarget = path.Join(remoteDir, resolvedTarget)
	}

	// A trailing separator marks the target as a directory even when it does
	// not exist yet; an existing remote directory is detected with a stat.
	targetIsDir := strings.HasSuffix(remoteTarget, "/")
	if remoteTarget != "" && !targetIsDir && isRemoteDir(channel, resolvedTarget) {
		targetIsDir = true
	}

	// A single source may target a file name; multiple sources require a
	// directory target (or none, in which case each source is uploaded under
	// its own basename).
	if len(matches) > 1 && remoteTarget != "" && !targetIsDir {
		return fmt.Errorf("cannot upload %d files to %s: not a directory", len(matches), remoteTarget)
	}

	for _, match := range matches {
		localFile := match
		if !filepath.IsAbs(localFile) {
			localFile = filepath.Join(localDir, localFile)
		}

		remoteFile := filepath.Base(match)
		switch {
		case remoteTarget == "":
			// The basename, uploaded into remoteDir below.
		case targetIsDir:
			remoteFile = path.Join(remoteTarget, remoteFile)
		default:
			remoteFile = remoteTarget
		}
		if !path.IsAbs(remoteFile) {
			remoteFile = path.Join(remoteDir, remoteFile)
		}

		if err := uploadOne(channel, localFile, remoteFile, recursive, follow, cancel); err != nil {
			return err
		}
	}
	return nil
}

// resolveLocalPath joins p with localDir when p is relative, returning p
// unchanged when it is absolute. localDir is the client's current local
// working directory, which is always absolute.
func resolveLocalPath(localDir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(localDir, p)
}

// globSplit reports whether arg contains unescaped glob metacharacters in its
// final path component and, if so, returns the directory prefix (before the
// last "/") and the pattern (the final component) to match against directory
// entries. Metacharacters escaped by a backslash (*, ?, [ preceded by \\,
// which makeargv preserves for glob matching) are literal and do not turn the
// argument into a glob. When arg has no unescaped metacharacters it returns
// ("", "", false).
func globSplit(arg string) (dir, pattern string, ok bool) {
	// The final path component starts after the last "/".
	slash := -1
	for i := 0; i < len(arg); i++ {
		if arg[i] == '/' {
			slash = i
		}
	}
	component := arg
	if slash >= 0 {
		component = arg[slash+1:]
	}

	hasMeta := false
	for i := 0; i < len(component); i++ {
		switch component[i] {
		case '\\':
			i++ // skip the escaped character: it is literal
		case '*', '?', '[':
			hasMeta = true
		}
	}
	if !hasMeta {
		return "", "", false
	}
	if slash < 0 {
		return "", arg, true
	}
	return arg[:slash], arg[slash+1:], true
}

func parseTransferArgs(parts []string, cmd string) (recursive bool, source string, target string, err error) {
	if len(parts) < 2 {
		return false, "", "", fmt.Errorf("usage: %s <source> [target]", cmd)
	}

	idx := 1
	for idx < len(parts) && strings.HasPrefix(parts[idx], "-") {
		if parts[idx] == "-r" || parts[idx] == "--recursive" {
			recursive = true
			idx++
			continue
		}
		return false, "", "", fmt.Errorf("usage: %s [-r] <source> [target]", cmd)
	}

	if idx >= len(parts) {
		return false, "", "", fmt.Errorf("usage: %s [-r] <source> [target]", cmd)
	}

	source = parts[idx]
	idx++
	if idx < len(parts) {
		target = parts[idx]
	}
	return recursive, source, target, nil
}

func downloadRecursive(channel ssh3.Channel, remotePath, localPath string, follow bool, cancel *transferCancel) error {
	if cancel.cancelled() {
		return ErrCancelled
	}

	// Resolve any server-side symbolic links on the way to remotePath. When
	// follow is false a trailing symlink is left unresolved so it can be
	// rejected below; when follow is true the client follows each link hop by
	// asking the server for its target.
	resolved, info, err := resolveRemote(channel, remotePath, follow)
	if err != nil {
		return err
	}
	if !follow && info != nil && info.IsSymlink {
		return fmt.Errorf("Cannot download %s: symbolic link", remotePath)
	}

	if info != nil && info.IsDir {
		if err := os.MkdirAll(localPath, 0o755); err != nil {
			return err
		}
		resp, err := doRequest(channel, &Request{Cmd: "ls", Path: resolved})
		if err != nil {
			return err
		}
		if !resp.OK {
			return serverError(resolved, resp.Error)
		}
		for _, entry := range resp.Entries {
			childRemote := path.Join(resolved, entry.Name)
			childLocal := filepath.Join(localPath, entry.Name)
			var err error
			switch {
			case entry.IsDir:
				// Recurse so the directory is walked and its files
				// downloaded.
				err = downloadRecursive(channel, childRemote, childLocal, follow, cancel)
			case entry.IsSymlink && !follow:
				return fmt.Errorf("Cannot download %s: symbolic link", childRemote)
			case entry.IsSymlink:
				// Recurse so the symlink is resolved (and followed if it points
				// to a directory, downloaded if it points to a file).
				err = downloadRecursive(channel, childRemote, childLocal, follow, cancel)
			default:
				err = downloadFileContents(channel, childRemote, childLocal, entry.Size, cancel)
			}
			if err != nil {
				// A permission-denied entry is reported and skipped so the
				// rest of the directory is still transferred.
				if isPermissionError(err) {
					fmt.Fprintf(os.Stderr, "get: %s\n", err)
					continue
				}
				return err
			}
		}
		return nil
	}

	var total int64
	if info != nil {
		total = info.Size
	}
	return downloadFileContents(channel, resolved, localPath, total, cancel)
}

// downloadFileContents downloads remotePath into localPath, displaying a
// per-file progress line (percentage and speed) as the transfer proceeds.
// total is the remote file size in bytes; 0 when it is unknown, in which case
// the progress line shows the transferred bytes and speed without a
// percentage.
//
// The transfer is pipelined: a window of read requests is kept in flight so
// the server is always working on the next chunk while earlier chunks are
// still in transit. The synchronous request/response loop this replaced (one
// round trip per chunk) is what capped the transfer speed: with the per-chunk
// serialisation overhead, throughput was bounded by ChunkSize/RTT regardless
// of the network bandwidth. The server answers requests strictly in order and
// returns an empty payload once the requested offset reaches the end of the
// file, so responses are consumed in request order and the first empty
// response terminates the transfer (responses already in flight beyond the
// end of the file are drained so no stray messages pollute the channel).
func downloadFileContents(channel ssh3.Channel, remotePath, localPath string, total int64, cancel *transferCancel) error {
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}

	f, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	prog := newProgress(filepath.Base(remotePath), total, os.Stdout, cancel)
	done := false
	defer func() {
		if !done {
			prog.abort()
		}
	}()

	// Issue the initial window of read requests at chunk-aligned offsets. The
	// stat that precedes this call provides the file size, which bounds the
	// window: tiny files do not need a full window of requests. When the size
	// is unknown a full window is issued; refilling is always driven by the
	// server's end-of-file response, so files that grow or shrink between the
	// stat and the transfer are still transferred fully.
	window := TransferWindow
	if total > 0 {
		if chunks := int((total + ChunkSize - 1) / ChunkSize); chunks < window {
			window = chunks
		}
	}
	sent := 0
	pending := 0
	for pending < window {
		if prog.cancelled() {
			// Remove the partially downloaded file so it is not mistaken for
			// a complete download.
			os.Remove(localPath)
			return ErrCancelled
		}
		if err := SendRequest(channel, &Request{Cmd: "get", Path: remotePath, Offset: int64(sent) * ChunkSize, Limit: ChunkSize}); err != nil {
			return err
		}
		sent++
		pending++
	}

	// Consume the responses in order, writing each chunk to the file, and keep
	// the window full by sending the next request as each response arrives.
	// drain consumes the responses still in flight for this transfer; it is
	// called on every error path below. The server answers strictly in request
	// order, so every response drained belongs to a request sent for
	// remotePath: without the drain the next transfer would mistake them for
	// its own responses (a denied file would wrongly deny the file after it).
	drain := func() {
		for pending > 0 {
			pending--
			if _, err := ReceiveResponse(channel); err != nil {
				break
			}
		}
	}
	var offset int64
	eof := false
	for pending > 0 {
		if prog.cancelled() {
			os.Remove(localPath)
			return ErrCancelled
		}
		resp, err := ReceiveResponse(channel)
		if err != nil {
			return err
		}
		pending--
		if !resp.OK {
			// The server denied this read (e.g. permission denied). Every
			// request in the window is denied too: drain them so the rest of
			// the directory is still transferred cleanly.
			err := serverError(remotePath, resp.Error)
			drain()
			return err
		}
		if len(resp.Data) == 0 {
			// End of file: stop refilling the window and drain the responses
			// already in flight (they are all empty as well).
			eof = true
			continue
		}
		if eof {
			// Defensive: no data should arrive after EOF; ignore it.
			continue
		}
		n, err := f.Write(resp.Data)
		if err != nil {
			drain()
			return err
		}
		offset += int64(n)
		prog.add(int64(n))
		// The response for the oldest request just arrived; send the next
		// request to keep the window full.
		if err := SendRequest(channel, &Request{Cmd: "get", Path: remotePath, Offset: int64(sent) * ChunkSize, Limit: ChunkSize}); err != nil {
			drain()
			return err
		}
		sent++
		pending++
	}
	prog.finish()
	fmt.Printf("Downloaded %s to %s (%d bytes)\n", remotePath, localPath, offset)
	done = true
	return nil
}

// uploadOne uploads localFile to remoteFile, descending into directories when
// recursive is set. It is the upload counterpart of downloadOne and is shared
// by the glob and non-glob paths of doPut.
func uploadOne(channel ssh3.Channel, localFile, remoteFile string, recursive, follow bool, cancel *transferCancel) error {
	if recursive {
		return uploadRecursive(channel, localFile, remoteFile, follow, cancel)
	}
	return uploadFile(channel, localFile, remoteFile, follow, cancel)
}

// statLocal reports the local FileInfo used to decide whether a path is a
// directory during an upload. With follow it uses stat (resolving symlinks, so
// a symlink to a directory is uploaded recursively); with follow=false it uses
// lstat so a symlink is seen as a symlink rather than its target.
func statLocal(p string, follow bool) (os.FileInfo, error) {
	if follow {
		return os.Stat(p)
	}
	return os.Lstat(p)
}

func uploadRecursive(channel ssh3.Channel, localPath, remotePath string, follow bool, cancel *transferCancel) error {
	if cancel.cancelled() {
		return ErrCancelled
	}
	info, err := statLocal(localPath, follow)
	if err != nil {
		return err
	}
	if !follow && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Cannot upload %s: symbolic link", localPath)
	}
	if !info.IsDir() {
		return uploadFile(channel, localPath, remotePath, follow, cancel)
	}
	if err := ensureRemoteDir(channel, remotePath); err != nil {
		return err
	}

	entries, err := os.ReadDir(localPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		childLocal := filepath.Join(localPath, entry.Name())
		childRemote := path.Join(remotePath, entry.Name())
		childInfo, err := statLocal(childLocal, follow)
		if err != nil {
			return err
		}
		if !follow && childInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Cannot upload %s: symbolic link", childLocal)
		}
		if childInfo.IsDir() {
			if err := uploadRecursive(channel, childLocal, childRemote, follow, cancel); err != nil {
				return err
			}
		} else if err := uploadFile(channel, childLocal, childRemote, follow, cancel); err != nil {
			return err
		}
	}
	return nil
}

func ensureRemoteDir(channel ssh3.Channel, remotePath string) error {
	if remotePath == "" || remotePath == "." || remotePath == "/" || remotePath == string(filepath.Separator) {
		return nil
	}

	resp, err := doRequest(channel, &Request{Cmd: "stat", Path: remotePath})
	if err != nil {
		return err
	}
	if resp.OK {
		if resp.Info != nil && resp.Info.IsDir {
			return nil
		}
		return fmt.Errorf("%s is not a directory", remotePath)
	}

	parent := path.Dir(remotePath)
	if parent != "." && parent != "/" && parent != remotePath {
		if err := ensureRemoteDir(channel, parent); err != nil {
			return err
		}
	}

	mkdirResp, err := doRequest(channel, &Request{Cmd: "mkdir", Path: remotePath})
	if err != nil {
		return err
	}
	if !mkdirResp.OK {
		return serverError(remotePath, mkdirResp.Error)
	}
	return nil
}

func printHelp() {
	fmt.Println(`Commands:
  cd [path]       change remote directory (no argument or "~" goes to $HOME,
                  "-" goes to the previous directory)
  ls [path]       list remote directory (path may contain * ? [glob] patterns)
  pwd             print remote working directory
  get [-r] <src> [dst]   download remote file or directory (src may contain * ? [glob] patterns)
  put [-r] <src> [dst]   upload local file or directory (src may contain * ? [glob] patterns)
  mkdir <path>    create remote directory
  rm <file>       remove remote file
  rmdir <dir>     remove remote directory
  lcd <path>      change local directory
  lls [path]      list local directory
  lpwd            print local working directory
  exit/quit       exit

Ctrl+C during a get/put cancels the transfer and returns to the prompt.

Symbolic links are followed by default: get resolves server-side links (the
server reports each link, the client follows it) and put resolves client-side
links, including inside recursive transfers. Start sshoq with
-no-follow-symlinks to disable this on the client: get then refuses to download
a server-side symlink and put refuses to upload a client-side symlink.

Paths are parsed like OpenSSH sftp: single quotes ('...') and double quotes
("...") protect spaces and metacharacters, and a backslash escapes the next
character (e.g. get 'Downloads/Test File.txt' or put Test\ File.txt).
A '#' outside quotes starts a comment. Tab completes file paths: local paths
for lcd/lls and for the source of put and target of get; remote paths for all
other arguments.

A leading "~" or "~/" in a path expands to the user's home directory: the
remote user's home for remote arguments (ls, mkdir, rm, rmdir, the source of
get and the target of put) and the local user's home for local arguments
(lcd, lls, the target of get and the source of put).`)
}

func printEntry(name string, info os.FileInfo) {
	fmt.Println(formatEntry(name, info))
}

// formatEntry renders one line of an ls listing, including the owning user
// and group (resolved to names when possible, numeric IDs otherwise).
func formatEntry(name string, info os.FileInfo) string {
	if info == nil {
		return name
	}
	mode := info.Mode().String()
	size := strconv.FormatInt(info.Size(), 10)
	mtime := info.ModTime().Format("Jan 02 15:04")
	user, group := entryOwnership(info)
	return fmt.Sprintf("%s %-10s %-10s %10s %s %s", mode, user, group, size, mtime, name)
}

// entryOwnership returns the display names of the owning user and group for a
// file. Remote entries carry the names sent by the server (with numeric-ID
// fallback); local entries resolve IDs through the local user database and
// fall back to numeric IDs.
func entryOwnership(info os.FileInfo) (user, group string) {
	if f, ok := info.(*sftpFileInfo); ok {
		user = f.userName
		group = f.groupName
		if user == "" {
			user = strconv.FormatUint(uint64(f.uid), 10)
		}
		if group == "" {
			group = strconv.FormatUint(uint64(f.gid), 10)
		}
		return user, group
	}

	uid, gid := ownershipFromInfo(info)
	user = strconv.FormatUint(uint64(uid), 10)
	group = strconv.FormatUint(uint64(gid), 10)
	if u, err := osuser.LookupId(user); err == nil && u.Username != "" {
		user = u.Username
	}
	if g, err := osuser.LookupGroupId(group); err == nil && g.Name != "" {
		group = g.Name
	}
	return user, group
}

func sftpFileInfoFromEntry(e FileInfo) os.FileInfo {
	return &sftpFileInfo{
		name:      e.Name,
		size:      e.Size,
		mode:      os.FileMode(e.Mode),
		modTime:   time.Unix(e.ModTime, 0),
		uid:       e.UID,
		gid:       e.GID,
		userName:  e.UserName,
		groupName: e.GroupName,
	}
}

type sftpFileInfo struct {
	name      string
	size      int64
	mode      os.FileMode
	modTime   time.Time
	uid       uint32
	gid       uint32
	userName  string
	groupName string
}

func (f *sftpFileInfo) Name() string       { return f.name }
func (f *sftpFileInfo) Size() int64        { return f.size }
func (f *sftpFileInfo) Mode() os.FileMode  { return f.mode }
func (f *sftpFileInfo) ModTime() time.Time { return f.modTime }
func (f *sftpFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f *sftpFileInfo) Sys() interface{}   { return nil }

func doRequest(channel ssh3.Channel, req *Request) (*Response, error) {
	if err := SendRequest(channel, req); err != nil {
		return nil, err
	}
	return ReceiveResponse(channel)
}

// serverError converts a non-OK server response into an error that names the
// filepath it concerns. Servers normally include the path in their error
// messages (any absolute path contains a "/"), but messages without one are
// prefixed with the path known to the client so errors like "too many levels
// of symbolic links" identify the file involved.
func serverError(path, msg string) error {
	if msg == "" {
		msg = "unknown error"
	}
	if path == "" || path == "." || path == "/" {
		return errors.New(msg)
	}
	if strings.Contains(msg, "/") || strings.Contains(msg, path) {
		return errors.New(msg)
	}
	return fmt.Errorf("%s: %s", path, msg)
}

// isPermissionError reports whether err is a permission failure: the read or
// listing of a file the user may not access, reported by the server, or a
// local permission error while creating the destination. The recursive
// download skips such entries and continues with the rest of the directory.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	// Server responses arrive as plain error strings (see serverError), so the
	// underlying syscall error is not available: match the message text that
	// EACCES and EPERM render as.
	msg := err.Error()
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted")
}

// downloadFile downloads remoteFile to localFile, resolving any server-side
// symbolic links by asking the server for each link's target (see resolveRemote)
// unless follow is false, in which case a trailing symlink is rejected rather
// than followed.
func downloadFile(channel ssh3.Channel, remotePath, localPath string, follow bool, cancel *transferCancel) error {
	resolved, info, err := resolveRemote(channel, remotePath, follow)
	if err != nil {
		return err
	}
	if !follow && info != nil && info.IsSymlink {
		return fmt.Errorf("Cannot download %s: symbolic link", remotePath)
	}
	if info != nil && info.IsDir {
		return fmt.Errorf("cannot download a directory: %s", remotePath)
	}

	var total int64
	if info != nil {
		total = info.Size
	}
	return downloadFileContents(channel, resolved, localPath, total, cancel)
}

// maxSymlinkFollow caps how many server-side symbolic links the client will
// follow while resolving a remote path, mirroring the kernel's ELOOP limit of
// 40 so a symlink loop is reported instead of looping forever.
const maxSymlinkFollow = 40

// resolveRemote follows symbolic links on the remote side one hop at a time,
// asking the server to stat the current path and, when it is a symlink, using
// the link target it returns as the next path. It returns the final resolved
// path and its FileInfo. When follow is false a trailing symlink is returned
// unresolved (with is-symlink set) so the caller can decide what to do.
// Symlink following is client-side: the server merely reports each next link
// to follow, so a client-side -no-follow switch can disable it.
func resolveRemote(channel ssh3.Channel, p string, follow bool) (string, *FileInfo, error) {
	cur := p
	for i := 0; i < maxSymlinkFollow; i++ {
		resp, err := doRequest(channel, &Request{Cmd: "stat", Path: cur})
		if err != nil {
			return "", nil, err
		}
		if !resp.OK {
			return "", nil, serverError(cur, resp.Error)
		}
		info := resp.Info
		if info == nil || !follow || !info.IsSymlink {
			return cur, info, nil
		}
		if info.LinkTarget == "" {
			return "", nil, fmt.Errorf("%s: empty symbolic link target", cur)
		}
		// Resolve the target against the symlink's own directory, mirroring
		// how the kernel resolves a relative link target.
		if path.IsAbs(info.LinkTarget) {
			cur = path.Clean(info.LinkTarget)
		} else {
			cur = path.Clean(path.Join(path.Dir(cur), info.LinkTarget))
		}
	}
	return "", nil, fmt.Errorf("%s: too many levels of symbolic links", p)
}

func uploadFile(channel ssh3.Channel, localPath, remotePath string, follow bool, cancel *transferCancel) error {
	// By default a client-side symbolic link is followed (its target is
	// uploaded); with follow=false a symlink is rejected rather than followed,
	// matching OpenSSH's put -P.
	if !follow {
		if fi, err := os.Lstat(localPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Cannot upload %s: symbolic link", localPath)
		}
	}

	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("cannot upload a directory: %s", localPath)
	}

	prog := newProgress(filepath.Base(localPath), info.Size(), os.Stdout, cancel)
	done := false
	defer func() {
		if !done {
			prog.abort()
		}
	}()

	// Pipelined upload, mirroring the download: a window of write requests is
	// kept in flight so the per-chunk round trip is amortised. The local file
	// size determines the number of chunks, so exactly the right number of
	// requests is issued and no stray responses are left on the channel.
	total := info.Size()
	chunks := int((total + ChunkSize - 1) / ChunkSize)
	window := TransferWindow
	if window > chunks {
		window = chunks
	}
	if window < 1 {
		window = 1
	}

	// readChunk reads the next chunk from the local file at its current
	// position and returns the bytes and the file offset at which they were
	// read. The offset is sent to the server so it writes at the right spot;
	// io.ReadFull guarantees every chunk except a short final one is a full
	// ChunkSize, so the offsets stay aligned with the server's writes. The
	// chunk buffer is allocated once and reused: SendRequest copies the data
	// into its frame synchronously, so the next read cannot clobber a chunk
	// that is still in flight.
	filePos := int64(0)
	chunkBuf := make([]byte, ChunkSize)
	readChunk := func() ([]byte, int64, error) {
		n, err := io.ReadFull(f, chunkBuf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return nil, 0, err
		}
		off := filePos
		filePos += int64(n)
		if n == 0 {
			return nil, off, nil // EOF: no more data
		}
		return chunkBuf[:n], off, nil
	}

	// Issue the initial window of write requests.
	nextChunk := 0
	pending := 0
	for pending < window && nextChunk < chunks {
		if prog.cancelled() {
			return ErrCancelled
		}
		data, off, err := readChunk()
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if err := SendRequest(channel, &Request{Cmd: "put", Path: remotePath, Offset: off, Data: data}); err != nil {
				return err
			}
		}
		nextChunk++
		pending++
	}

	// Consume the acknowledgements in order and refill the window as each one
	// arrives. The response for chunk i acknowledges exactly
	// min(ChunkSize, total-i*ChunkSize) bytes, so the progress display is
	// updated as the server confirms each chunk.
	acked := 0
	for pending > 0 {
		if prog.cancelled() {
			return ErrCancelled
		}
		resp, err := ReceiveResponse(channel)
		if err != nil {
			return err
		}
		if !resp.OK {
			return serverError(remotePath, resp.Error)
		}
		n := int64(ChunkSize)
		if remaining := total - int64(acked)*ChunkSize; remaining < n {
			n = remaining
		}
		if n > 0 {
			prog.add(n)
		}
		acked++
		pending--
		if nextChunk < chunks {
			data, off, err := readChunk()
			if err != nil {
				return err
			}
			if len(data) > 0 {
				if err := SendRequest(channel, &Request{Cmd: "put", Path: remotePath, Offset: off, Data: data}); err != nil {
					return err
				}
			}
			nextChunk++
			pending++
		}
	}
	prog.finish()
	fmt.Printf("Uploaded %s to %s (%d bytes)\n", localPath, remotePath, filePos)
	done = true
	return nil
}
