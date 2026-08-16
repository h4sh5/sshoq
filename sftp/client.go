package sftp

import (
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

	ssh3 "github.com/h4sh5/sshoq"
	"github.com/h4sh5/sshoq/client"
)

func RunInteractiveClient(c *client.Client) error {
	channel, err := c.OpenChannel("sftp", 30000, 0)
	if err != nil {
		return fmt.Errorf("could not open sftp channel: %w", err)
	}
	defer channel.Close()
	if err := channel.WaitOpen(); err != nil {
		return fmt.Errorf("could not open sftp channel: %w", err)
	}

	localDir, _ := os.Getwd()
	remoteDir := "."

	input, err := newInteractiveReader()
	if err != nil {
		return err
	}
	defer input.close()
	if input.editor != nil {
		input.editor.completer = newCompleter(channel, &localDir, &remoteDir)
	}

	for {
		line, err := input.readLine("sftp> ")
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]

		switch cmd {
		case "exit", "quit":
			return nil

		case "lcd":
			if len(parts) < 2 {
				fmt.Println("usage: lcd <local-path>")
				continue
			}
			if err := os.Chdir(parts[1]); err != nil {
				fmt.Fprintf(os.Stderr, "lcd: %s\n", err)
			} else {
				localDir, _ = os.Getwd()
			}

		case "lls":
			target := localDir
			if len(parts) > 1 {
				target = filepath.Join(localDir, parts[1])
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
			target := remoteDir
			if len(parts) > 1 {
				if path.IsAbs(parts[1]) {
					target = parts[1]
				} else {
					target = path.Join(remoteDir, parts[1])
				}
			}
			resp, err := doRequest(channel, &Request{Cmd: "cd", Path: target})
			if err != nil {
				fmt.Fprintf(os.Stderr, "cd: %s\n", err)
				continue
			}
			if !resp.OK {
				fmt.Fprintf(os.Stderr, "cd: %s\n", resp.Error)
			} else {
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
			if err := doGet(channel, localDir, remoteDir, parts); err != nil {
				fmt.Fprintf(os.Stderr, "get: %s\n", err)
				continue
			}

		case "put":
			recursive, localSource, remoteTarget, err := parseTransferArgs(parts, "put")
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			localFile := localSource
			if !filepath.IsAbs(localFile) {
				localFile = filepath.Join(localDir, localFile)
			}
			remoteFile := remoteTarget
			if remoteFile == "" {
				remoteFile = filepath.Base(localFile)
			}
			if !path.IsAbs(remoteFile) {
				remoteFile = path.Join(remoteDir, remoteFile)
			}

			if recursive {
				if err := uploadRecursive(channel, localFile, remoteFile); err != nil {
					fmt.Fprintf(os.Stderr, "put: %s\n", err)
				}
			} else if err := uploadFile(channel, localFile, remoteFile); err != nil {
				fmt.Fprintf(os.Stderr, "put: %s\n", err)
			}

		case "mkdir":
			if len(parts) < 2 {
				fmt.Println("usage: mkdir <remote-path>")
				continue
			}
			target := parts[1]
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
			target := parts[1]
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
			target := parts[1]
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

// newCompleter builds the tab-completion callback for the interactive SFTP
// shell. It completes remote paths (resolved against *remoteDir, listed over
// the sftp channel) for commands that operate on the remote filesystem, and
// local paths (resolved against *localDir) for lcd/lls; for get and put the
// source argument is completed on the source side and the target argument on
// the target side. Candidates are full replacements for the word being edited,
// with directories ending in "/".
func newCompleter(channel ssh3.Channel, localDir, remoteDir *string) completeFunc {
	listRemote := func(dir string) ([]string, error) {
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
			return nil, fmt.Errorf("%s", resp.Error)
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
		// The word to complete is the whitespace-delimited token ending at the
		// cursor. When the cursor sits on the command itself there is nothing
		// to complete: only paths are completed, not commands.
		wordStart := pos
		for wordStart > 0 && !unicode.IsSpace(buf[wordStart-1]) {
			wordStart--
		}
		if wordStart == 0 {
			return nil, 0
		}
		word := string(buf[wordStart:pos])

		args := strings.Fields(string(buf[:pos]))
		if len(args) == 0 {
			return nil, wordStart
		}
		cmd := args[0]

		// The argument ordinal occupied by the word (1 = first argument),
		// skipping flag arguments such as -r/--recursive.
		argIdx := 1
		for _, a := range args[1:] {
			if a == word {
				break
			}
			if !strings.HasPrefix(a, "-") {
				argIdx++
			}
		}
		if strings.HasPrefix(word, "-") {
			return nil, wordStart
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
			return nil, wordStart
		}

		listDir := listRemote
		if local {
			listDir = listLocal
		}
		return completePath(word, listDir), wordStart
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
	if i := strings.LastIndex(word, "/"); i >= 0 {
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
		return fmt.Errorf("%s", resp.Error)
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

// doGet downloads a remote file or directory, or every entry in the resolved
// source directory whose name matches a glob pattern. It mirrors doLs: when the
// remote source contains glob metacharacters in its final path component (*, ?,
// [range]) the source is split into the directory to list and a pattern to
// filter its entries via globSplit, and each matching entry is downloaded. An
// un-globbed source is downloaded directly, preserving the previous behavior.
// The -r flag is honored in both cases: directories (whether matched by the
// pattern or named directly) are transferred recursively via downloadOne.
func doGet(channel ssh3.Channel, localDir, remoteDir string, parts []string) error {
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
			return fmt.Errorf("%s", resp.Error)
		}
		for _, e := range resp.Entries {
			ok, err := path.Match(pattern, e.Name)
			if err != nil {
				return fmt.Errorf("invalid pattern \"%s\": %w", pattern, err)
			}
			if !ok {
				continue
			}
			remoteFile := path.Join(sourceDir, e.Name)
			localFile := filepath.Join(localDir, filepath.Base(filepath.Clean(remoteFile)))
			if err := downloadOne(channel, remoteFile, localFile, recursive); err != nil {
				return err
			}
		}
		return nil
	}

	// No glob: preserve the previous single-target behavior.
	remoteFile := sourceDir
	localFile := localTarget
	if localFile == "" {
		localFile = filepath.Base(filepath.Clean(remoteFile))
	}
	localFile = filepath.Join(localDir, localFile)
	return downloadOne(channel, remoteFile, localFile, recursive)
}

// downloadOne downloads remoteFile to localFile, descending into directories when
// recursive is set. It reproduces the transfer behavior of a non-glob "get" and
// is shared by the glob and non-glob paths of doGet so that wildcards work the
// same way with and without -r.
func downloadOne(channel ssh3.Channel, remoteFile, localFile string, recursive bool) error {
	if recursive {
		return downloadRecursive(channel, remoteFile, localFile)
	}
	return downloadFile(channel, remoteFile, localFile)
}

// globSplit reports whether arg contains glob metacharacters in its final path
// component and, if so, returns the directory prefix (before the last "/") and
// the pattern (the final component) to match against directory entries. When arg
// has no metacharacters it returns ("", "", false).
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

	for i := 0; i < len(component); i++ {
		switch component[i] {
		case '*', '?', '[':
			if slash < 0 {
				return "", arg, true
			}
			return arg[:slash], arg[slash+1:], true
		}
	}
	return "", "", false
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

func downloadRecursive(channel ssh3.Channel, remotePath, localPath string) error {
	statResp, err := doRequest(channel, &Request{Cmd: "stat", Path: remotePath})
	if err != nil {
		return err
	}
	if !statResp.OK {
		return fmt.Errorf("%s", statResp.Error)
	}
	if statResp.Info != nil && statResp.Info.IsDir {
		if err := os.MkdirAll(localPath, 0o755); err != nil {
			return err
		}
		resp, err := doRequest(channel, &Request{Cmd: "ls", Path: remotePath})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		for _, entry := range resp.Entries {
			childRemote := path.Join(remotePath, entry.Name)
			childLocal := filepath.Join(localPath, entry.Name)
			if entry.IsDir {
				if err := downloadRecursive(channel, childRemote, childLocal); err != nil {
					return err
				}
			} else if err := downloadFileContents(channel, childRemote, childLocal, nil); err != nil {
				return err
			}
		}
		return nil
	}

	return downloadFileContents(channel, remotePath, localPath, statResp.Info)
}

func downloadFileContents(channel ssh3.Channel, remotePath, localPath string, info *FileInfo) error {
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}

	f, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	var offset int64
	for {
		resp, err := doRequest(channel, &Request{Cmd: "get", Path: remotePath, Offset: offset, Limit: ChunkSize})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		if len(resp.Data) == 0 {
			break
		}
		n, err := f.Write(resp.Data)
		if err != nil {
			return err
		}
		offset += int64(n)
	}
	fmt.Printf("Downloaded %s to %s (%d bytes)\n", remotePath, localPath, offset)
	return nil
}

func uploadRecursive(channel ssh3.Channel, localPath, remotePath string) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return uploadFile(channel, localPath, remotePath)
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
		childInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if childInfo.IsDir() {
			if err := uploadRecursive(channel, childLocal, childRemote); err != nil {
				return err
			}
		} else if err := uploadFile(channel, childLocal, childRemote); err != nil {
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
		return fmt.Errorf("%s", mkdirResp.Error)
	}
	return nil
}

func printHelp() {
	fmt.Println(`Commands:
  cd <path>       change remote directory
  ls [path]       list remote directory (path may contain * ? [glob] patterns)
  pwd             print remote working directory
  get [-r] <src> [dst]   download remote file or directory (src may contain * ? [glob] patterns)
  put [-r] <src> [dst]   upload local file or directory
  mkdir <path>    create remote directory
  rm <file>       remove remote file
  rmdir <dir>     remove remote directory
  lcd <path>      change local directory
  lls [path]      list local directory
  lpwd            print local working directory
  exit/quit       exit

Tab completes file paths: local paths for lcd/lls and for the source of put
and target of get; remote paths for all other arguments.`)
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

func downloadFile(channel ssh3.Channel, remotePath, localPath string) error {
	statResp, err := doRequest(channel, &Request{Cmd: "stat", Path: remotePath})
	if err != nil {
		return err
	}
	if !statResp.OK {
		return fmt.Errorf("%s", statResp.Error)
	}
	if statResp.Info != nil && statResp.Info.IsDir {
		return fmt.Errorf("cannot download a directory")
	}

	return downloadFileContents(channel, remotePath, localPath, statResp.Info)
}

func uploadFile(channel ssh3.Channel, localPath, remotePath string) error {
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
		return fmt.Errorf("cannot upload a directory")
	}

	var offset int64
	buf := make([]byte, ChunkSize)
	for {
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n > 0 {
			resp, err := doRequest(channel, &Request{Cmd: "put", Path: remotePath, Offset: offset, Data: buf[:n]})
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("%s", resp.Error)
			}
			offset += int64(n)
		}
		if err == io.EOF {
			break
		}
	}
	fmt.Printf("Uploaded %s to %s (%d bytes)\n", localPath, remotePath, offset)
	return nil
}
