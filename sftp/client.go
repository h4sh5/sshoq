package sftp

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Printf("sftp> ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
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
			target := remoteDir
			if len(parts) > 1 {
				if path.IsAbs(parts[1]) {
					target = parts[1]
				} else {
					target = path.Join(remoteDir, parts[1])
				}
			}
			resp, err := doRequest(channel, &Request{Cmd: "ls", Path: target})
			if err != nil {
				fmt.Fprintf(os.Stderr, "ls: %s\n", err)
				continue
			}
			if !resp.OK {
				fmt.Fprintf(os.Stderr, "ls: %s\n", resp.Error)
				continue
			}
			for _, e := range resp.Entries {
				printEntry(e.Name, sftpFileInfoFromEntry(e))
			}

		case "get":
			recursive, remoteSource, localTarget, err := parseTransferArgs(parts, "get")
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			remoteFile := remoteSource
			if !path.IsAbs(remoteFile) {
				remoteFile = path.Join(remoteDir, remoteFile)
			}
			localFile := localTarget
			if localFile == "" {
				localFile = filepath.Base(filepath.Clean(remoteFile))
			}
			localFile = filepath.Join(localDir, localFile)

			if recursive {
				if err := downloadRecursive(channel, remoteFile, localFile); err != nil {
					fmt.Fprintf(os.Stderr, "get: %s\n", err)
				}
			} else if err := downloadFile(channel, remoteFile, localFile); err != nil {
				fmt.Fprintf(os.Stderr, "get: %s\n", err)
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

	return scanner.Err()
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
  ls [path]       list remote directory
  pwd             print remote working directory
  get [-r] <src> [dst]   download remote file or directory
  put [-r] <src> [dst]   upload local file or directory
  mkdir <path>    create remote directory
  rm <file>       remove remote file
  rmdir <dir>     remove remote directory
  lcd <path>      change local directory
  lls [path]      list local directory
  lpwd            print local working directory
  exit/quit       exit`)
}

func printEntry(name string, info os.FileInfo) {
	if info == nil {
		fmt.Println(name)
		return
	}
	mode := info.Mode().String()
	size := strconv.FormatInt(info.Size(), 10)
	mtime := info.ModTime().Format("Jan 02 15:04")
	fmt.Printf("%s %10s %s %s\n", mode, size, mtime, name)
}

func sftpFileInfoFromEntry(e FileInfo) os.FileInfo {
	return &sftpFileInfo{
		name:    e.Name,
		size:    e.Size,
		mode:    os.FileMode(e.Mode),
		modTime: time.Unix(e.ModTime, 0),
	}
}

type sftpFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
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
