package integration_tests

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var ssh3Path string
var ssh3ServerPath string

const DEFAULT_URL_PATH = "/sshoq-tests"
const DEFAULT_PROXY_URL_PATH = "/sshoq-tests-proxy"

var serverCommand *exec.Cmd
var serverSessions map[string]*Session = make(map[string]*Session) // bind address to session
var proxyServerCommand *exec.Cmd
var proxyServerSession *Session
var rsaPrivKeyPath string
var ed25519PrivKeyPath string
var ecdsaPrivKeyPath string
var attackerPrivKeyPath string
var username string
var ecdsaUsername string

const serverBind = "127.0.0.1:4433"
const serverBindSFTPDisabled = "127.0.0.1:4434"
const proxyServerBind = "127.0.0.1:4444"

var oldServerBinds map[string]string = map[string]string{
	"v0.1.8":  "127.0.0.1:5000",
	"v0.1.10": "127.0.0.1:5001",
} // tag version to bind string

func IPv6LoopbackAvailable(addrs []net.Addr) bool {
	for _, addr := range addrs {
		Expect(addr).To(BeAssignableToTypeOf(&net.IPNet{}))
		ip := addr.(*net.IPNet).IP
		if ip.To4() == nil && ip.To16() != nil && ip.IsLoopback() {
			// we found ::1, we can start the test
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

var _ = BeforeSuite(func() {
	var err error
	ssh3Path, err = Build("../cmd/sshoq/main.go")
	Expect(err).ToNot(HaveOccurred())
	if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") == "1" {
		// Tests implying a server will only work on Linux
		// (the server currently only builds on Linux)
		// and the server needs root priviledges, so we only
		// run them is they are enabled explicitly.
		ssh3ServerPath, err = BuildWithEnvironment("../cmd/sshoq-server/main.go", []string{fmt.Sprintf("CGO_ENABLED=%s", os.Getenv("CGO_ENABLED"))})
		Expect(err).ToNot(HaveOccurred())

		// The SFTP handler is served in a forked child process that runs with
		// the authenticated user's UID/GID (see sftp.ServeChannel), so the
		// server binary must be reachable and executable by that user. gexec
		// compiles the binary into a chain of 0700 temp directories
		// (/tmp/gexec_artifacts*/g*), which would prevent the child from being
		// spawned (fork/exec: permission denied); open up every ancestor
		// directory and the binary itself so SFTP sessions (e.g. -sftp or
		// -scp) can run in the integration tests.
		for dir := filepath.Dir(ssh3ServerPath); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
			Expect(os.Chmod(dir, 0o755)).To(Succeed())
		}
		Expect(os.Chmod(ssh3ServerPath, 0o755)).To(Succeed())
		serverCommand = exec.Command(ssh3ServerPath,
			"-bind", serverBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		serverCommand.Env = append(serverCommand.Env, "SSH3_LOG_LEVEL=debug")
		session, err := Start(serverCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[serverBind] = session

		disabledSFTPServerCommand := exec.Command(ssh3ServerPath,
			"-bind", serverBindSFTPDisabled,
			"-v",
			"-enable-password-login",
			"-disable-sftp",
			"-url-path", DEFAULT_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		disabledSFTPServerCommand.Env = append(disabledSFTPServerCommand.Env, "SSH3_LOG_LEVEL=debug")
		session, err = Start(disabledSFTPServerCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[serverBindSFTPDisabled] = session

		for tag, bind := range oldServerBinds {
			gobin, err := os.MkdirTemp("", fmt.Sprintf("sshoq-backwards-compatible-versions-%s", tag))
			Expect(err).ToNot(HaveOccurred())
			cmd := exec.Command("go", "install", fmt.Sprintf("github.com/h4sh5/sshoq/cmd/sshoq-server@%s", tag))
			cmd.Env = os.Environ()
			cmd.Env = append(cmd.Env, fmt.Sprintf("GOBIN=%s", gobin))
			err = cmd.Run()
			Expect(err).ToNot(HaveOccurred())
			serverPath := path.Join(gobin, "sshoq-server")
			Expect(err).ToNot(HaveOccurred())
			backwardsCompatibleServerCommand := exec.Command(serverPath,
				"-bind", bind,
				"-v",
				"-enable-password-login",
				"-url-path", DEFAULT_URL_PATH,
				"-cert", os.Getenv("CERT_PEM"),
				"-key", os.Getenv("CERT_PRIV_KEY"))
			serverCommand.Env = append(backwardsCompatibleServerCommand.Env, "SSH3_LOG_LEVEL=debug")
			session, err = Start(backwardsCompatibleServerCommand, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			serverSessions[bind] = session
		}

		proxyServerCommand = exec.Command(ssh3ServerPath,
			"-bind", proxyServerBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_PROXY_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		proxyServerCommand.Env = append(proxyServerCommand.Env, "SSH3_LOG_LEVEL=debug")
		proxyServerSession, err = Start(proxyServerCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[proxyServerBind] = proxyServerSession

		rsaPrivKeyPath = os.Getenv("TESTUSER_PRIVKEY")
		ed25519PrivKeyPath = os.Getenv("TESTUSER_ED25519_PRIVKEY")
		ecdsaPrivKeyPath = os.Getenv("TESTUSER_ECDSA_PRIVKEY")
		attackerPrivKeyPath = os.Getenv("ATTACKER_PRIVKEY")
		username = os.Getenv("TESTUSER_USERNAME")
		ecdsaUsername = os.Getenv("ECDSATESTUSER_USERNAME")
		Expect(fileExists(rsaPrivKeyPath)).To(BeTrue())
		Expect(fileExists(attackerPrivKeyPath)).To(BeTrue())
		err = os.WriteFile(fmt.Sprintf("/home/%s/.profile", username), []byte("echo 'hello from .profile'"), 0777)
		Expect(err).ToNot(HaveOccurred())
	}
})

var _ = AfterSuite(func() {
	CleanupBuildArtifacts()
	for _, serverSession := range serverSessions {
		serverSession.Terminate()
	}
})

var _ = Describe("Testing the sshoq cli", func() {

	Context("Usage", func() {
		It("Displays the help", func() {
			command := exec.Command(ssh3Path, "-h")
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session, "5s").Should(Exit(0))
			Expect(session.Err.Contents()).To(ContainSubstring("Usage of"))
		})
	})

	Context("With running server", func() {
		BeforeEach(func() {
			if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") != "1" {
				Skip("skipping integration tests")
			}
			Consistently(serverSessions[serverBind], "200ms").ShouldNot(Exit())
		})

		Context("Insecure", func() {
			var clientArgs []string
			getClientArgsWithBind := func(privKeyPath string, bind string, additionalArgs ...string) []string {
				args := []string{
					"-v",
					"-insecure",
					"-i", privKeyPath,
				}
				args = append(args, additionalArgs...)
				args = append(args, fmt.Sprintf("%s@%s%s", username, bind, DEFAULT_URL_PATH))
				return args
			}
			getClientArgs := func(privKeyPath string, additionalArgs ...string) []string {
				return getClientArgsWithBind(privKeyPath, serverBind, additionalArgs...)
			}

			Context("Client behaviour", func() {
				It("Should connect using an RSA privkey", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an RSA privkey through proxy jump", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH)), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				for key, val := range oldServerBinds {
					// actually capture the values of key,val, as directly referring them in the code below will only keep the value of the last iteration
					tag, bind := key, val
					When("server version is"+tag+", bind is"+bind, func() {
						It("Should connect using an RSA privkey to old supported server", func() {
							clientArgs = append(getClientArgsWithBind(rsaPrivKeyPath, bind), "echo", "Hello, World!")
							command := exec.Command(ssh3Path, clientArgs...)
							session, err := Start(command, GinkgoWriter, GinkgoWriter)
							Expect(err).ToNot(HaveOccurred())
							Eventually(session).Should(Exit(0))
							Eventually(session).Should(Say("Hello, World!\n"))
						})
					})
				}

				It("Should connect using an ed25519 privkey", func() {
					clientArgs = append(getClientArgs(ed25519PrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an ecdsa privkey", func() {
					// for retrocopatibility integration tests with version 0.1.5, we must perform ecdsa tests
					// for another user as ecdsa is not available on the server on older versions
					savedUsername := username
					username = ecdsaUsername
					clientArgs = append(getClientArgs(ecdsaPrivKeyPath), "echo", "Hello, World!")
					username = savedUsername
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should return a useful error when SFTP is disabled on the server", func() {
					clientArgs = getClientArgsWithBind(rsaPrivKeyPath, serverBindSFTPDisabled, "-sftp")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))
					Eventually(session.Err).Should(Say("could not open sftp channel: .*SFTP is disabled on the server"))
				})

				It("Should return the correct exit status", func() {
					clientArgs0 := append(getClientArgs(rsaPrivKeyPath), "exit", "0")
					clientArgs1 := append(getClientArgs(rsaPrivKeyPath), "exit", "1")
					clientArgs255 := append(getClientArgs(rsaPrivKeyPath), "exit", "255")
					clientArgsMinus1 := append(getClientArgs(rsaPrivKeyPath), "exit", "-1")

					command0 := exec.Command(ssh3Path, clientArgs0...)
					session, err := Start(command0, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))

					command1 := exec.Command(ssh3Path, clientArgs1...)
					session, err = Start(command1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(1))

					command255 := exec.Command(ssh3Path, clientArgs255...)
					session, err = Start(command255, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))

					commandMinus1 := exec.Command(ssh3Path, clientArgsMinus1...)
					session, err = Start(commandMinus1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))
				})

				It("Should run the interactive shell in login mode and read .profile", func() {
					clientArgs = getClientArgs(rsaPrivKeyPath)
					command := exec.Command(ssh3Path, clientArgs...)
					stdin, err := command.StdinPipe()
					Expect(err).ToNot(HaveOccurred())
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Consistently(session).ShouldNot(Exit())
					Eventually(session.Out).Should(Say("hello from .profile"))
					_, err = stdin.Write([]byte("exit\n")) // 0x04 = EOT character, closing the bash session
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
				})

				// It checks the client with the -forward-tcp or -reverse-tcp forwarding options.
				// As forward-tcp, a TCP socket is indeed well open on the client and is forwarded
				// through the SSH3 connection towards the specified remote IP and port at server´s reach.
				// When reverse-tcp is specified, a TCP socket is open on the server and forwarded through
				// the SSH3 connection towards the specified remote IP and port at client's reach.
				// As the server and the client are run on the same machine the same test can be reused
				// for both cases.
				Context("TCP port forwarding", func() {
					testTCPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.TCPAddr, messageFromClient string, messageFromServer string, forwardingType string) {
						localIP := "[::1]"
						if remoteAddr.IP.To4() != nil {
							localIP = "127.0.0.1"
						}
						serverStarted := make(chan struct{})
						done := make(chan struct{})
						// Start a TCP server on the specified remote IP and port
						go func() {
							defer close(done)
							defer close(serverStarted)
							defer GinkgoRecover()
							listener, err := net.ListenTCP("tcp", remoteAddr)
							Expect(err).ToNot(HaveOccurred())
							defer listener.Close()

							serverStarted <- struct{}{}

							conn, err := listener.Accept()
							Expect(err).ToNot(HaveOccurred())
							defer conn.Close()

							// Read message from client
							buffer := make([]byte, len(messageFromClient))
							_, err = conn.Read(buffer)
							Expect(err).ToNot(HaveOccurred())
							Expect(string(buffer)).To(Equal(messageFromClient))

							// Send message to client
							_, err = conn.Write([]byte(messageFromServer))
							Expect(err).ToNot(HaveOccurred())
							conn.(*net.TCPConn).CloseWrite()

							// Read from the client after receiving the message, assert EOF
							n, err := conn.Read(buffer)
							Expect(err).To(Equal(io.EOF))
							Expect(n).To(Equal(0))
						}()

						Eventually(serverStarted).Should(Receive())
						// Execute the client with TCP port forwarding

						additionalArgs := []string{}
						if proxyJump {
							additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
						}
						if remoteAddr.IP.To4() == nil {
							// with an IPv6 remote address, also bind the local forward socket on
							// the IPv6 loopback (4-parts syntax: bindAddress@localPort@remoteIP@remotePort)
							additionalArgs = append(additionalArgs, forwardingType, fmt.Sprintf("::1@%d@%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
						} else {
							additionalArgs = append(additionalArgs, forwardingType, fmt.Sprintf("%d@%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
						}
						clientArgs := getClientArgs(rsaPrivKeyPath, additionalArgs...)
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()

						// Try to connect to the local forwarded port
						localAddr := fmt.Sprintf("%s:%d", localIP, localPort)
						var conn net.Conn
						// connection refused might happen betwen the time when the process starts and actually listens the socket
						Eventually(func() error {
							var err error
							conn, err = net.Dial("tcp", localAddr)
							return err
						}).ShouldNot(HaveOccurred())
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()

						// Send message from client
						n, err := conn.Write([]byte(messageFromClient))
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(len(messageFromClient)))

						// Close the client-side connection
						conn.(*net.TCPConn).CloseWrite()

						// Read message from server. The client may deliver the last data together
						// with the EOF (it half-closes the socket right after writing the final
						// data), so a read returning data and io.EOF at once is expected and must
						// not be treated as an error.
						buffer := make([]byte, len(messageFromServer))
						conn.SetReadDeadline(time.Now().Add(1 * time.Second))
						total := 0
						for total < len(buffer) {
							n, err = conn.Read(buffer[total:])
							total += n
							if err != nil {
								Expect(err).To(SatisfyAny(BeNil(), Equal(io.EOF)))
								break
							}
						}
						Expect(total).To(Equal(len(messageFromServer)))
						Expect(string(buffer)).To(Equal(messageFromServer))

						// If the messages are correctly exchanged, the forwarding is working as expected
						// Now, check that the TCP conn is well closed and that no additional byte was sent
						n, err = conn.Read(buffer)
						Expect(n).To(Equal(0))
						Expect(err).To(Equal(io.EOF))

						// wait for the remote goroutine to finish: its listener is bound on the
						// shared remote port, and the next sub-test reuses the same port
						Eventually(done).Should(BeClosed())
					}

					It("works with small messages", func() {
						testTCPPortForwarding(8080, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-forward-tcp")
						testTCPPortForwarding(8090, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-reverse-tcp")
					})

					It("works through proxy jump", func() {
						testTCPPortForwarding(8080, true, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-forward-tcp")
						testTCPPortForwarding(8091, true, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-reverse-tcp")
					})

					It("works with messages larger than a typical MTU", func() {
						rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
						messageFromClient := make([]byte, 20000)
						messageFromServer := make([]byte, 20000)
						n, err := rng.Read(messageFromClient)
						Expect(n).To(Equal(len(messageFromClient)))
						Expect(err).ToNot(HaveOccurred())
						n, err = rng.Read(messageFromServer)
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(err).ToNot(HaveOccurred())
						testTCPPortForwarding(8081, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer), "-forward-tcp")
						testTCPPortForwarding(8092, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer), "-reverse-tcp")
					})

					It("works with IPv6 addresses", func() {
						// we first have to check whether IPv6 are enabled on that host, it is still often
						// not the case in many Docker containers...
						addrs, err := net.InterfaceAddrs()
						Expect(err).ToNot(HaveOccurred())
						if !IPv6LoopbackAvailable(addrs) {
							Skip("IPv6 not available on this host")
						}
						testTCPPortForwarding(8082, false, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9090}, "hello from client", "hello from server", "-forward-tcp")
						testTCPPortForwarding(8093, false, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9090}, "hello from client", "hello from server", "-reverse-tcp")
					})

					// tcpForwardingSpec describes one TCP port forwarding used by the
					// multiple-forwarding tests: either a local forward (-L) or a
					// reverse forward (-R).
					type tcpForwardingSpec struct {
						forwardingType    string // "-forward-tcp" or "-reverse-tcp"
						localPort         uint16 // bound on the client (-L) or on the server (-R)
						remotePort        uint16 // destination at server's reach (-L) or at client's reach (-R)
						messageFromClient string
						messageFromServer string
					}

					// testMultipleTCPPortForwardings starts a single client that sets up
					// several TCP port forwardings at once (multiple -forward-tcp/-L
					// and/or -reverse-tcp/-R flags) and checks that every forwarding
					// works concurrently.
					testMultipleTCPPortForwardings := func(forwardings []tcpForwardingSpec) {
						const bindIP = "127.0.0.1"

						serverStarted := make(chan struct{}, len(forwardings))
						done := make(chan struct{}, len(forwardings))
						errCh := make(chan error, len(forwardings))

						// Start one target TCP server per forwarding
						for _, fwd := range forwardings {
							fwd := fwd
							go func() {
								defer GinkgoRecover()
								listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(bindIP), Port: int(fwd.remotePort)})
								if err != nil {
									errCh <- err
									return
								}
								defer listener.Close()
								serverStarted <- struct{}{}

								conn, err := listener.Accept()
								if err != nil {
									errCh <- err
									return
								}
								defer conn.Close()

								// Read the message coming from the client through the tunnel
								buffer := make([]byte, len(fwd.messageFromClient))
								if _, err := io.ReadFull(conn, buffer); err != nil {
									errCh <- err
									return
								}
								if string(buffer) != fwd.messageFromClient {
									errCh <- fmt.Errorf("target %d: got %q, want %q", fwd.remotePort, buffer, fwd.messageFromClient)
									return
								}

								// Send a message back through the tunnel
								if _, err := conn.Write([]byte(fwd.messageFromServer)); err != nil {
									errCh <- err
									return
								}
								conn.(*net.TCPConn).CloseWrite()

								// The client must close its side once the exchange is over
								n, err := conn.Read(buffer)
								if err != io.EOF || n != 0 {
									errCh <- fmt.Errorf("target %d: expected EOF, got n=%d err=%v", fwd.remotePort, n, err)
									return
								}
								done <- struct{}{}
							}()
						}

						// Wait for all the target servers to be ready
						for range forwardings {
							Eventually(serverStarted).Should(Receive())
						}

						// Start the client with every forwarding declared at once
						additionalArgs := []string{}
						for _, fwd := range forwardings {
							additionalArgs = append(additionalArgs, fwd.forwardingType, fmt.Sprintf("%d@%s@%d", fwd.localPort, bindIP, fwd.remotePort))
						}
						clientArgs := getClientArgs(rsaPrivKeyPath, additionalArgs...)
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()

						// Connect to every forwarded port and exchange messages through each tunnel
						for _, fwd := range forwardings {
							func() {
								localAddr := fmt.Sprintf("%s:%d", bindIP, fwd.localPort)
								var conn net.Conn
								// connection refused might happen between the time the process
								// starts and actually listens the socket
								Eventually(func() error {
									var err error
									conn, err = net.Dial("tcp", localAddr)
									return err
								}).ShouldNot(HaveOccurred())
								defer conn.Close()

								n, err := conn.Write([]byte(fwd.messageFromClient))
								Expect(err).ToNot(HaveOccurred())
								Expect(n).To(Equal(len(fwd.messageFromClient)))
								conn.(*net.TCPConn).CloseWrite()

								buffer := make([]byte, len(fwd.messageFromServer))
								conn.SetReadDeadline(time.Now().Add(2 * time.Second))
								total := 0
								for total < len(buffer) {
									n, err = conn.Read(buffer[total:])
									total += n
									if err != nil {
										Expect(err).To(SatisfyAny(BeNil(), Equal(io.EOF)))
										break
									}
								}
								Expect(total).To(Equal(len(fwd.messageFromServer)))
								Expect(string(buffer)).To(Equal(fwd.messageFromServer))

								// The tunnel must be closed on both sides: no extra byte
								n, err = conn.Read(buffer)
								Expect(n).To(Equal(0))
								Expect(err).To(Equal(io.EOF))
							}()
						}

						// Every target server must have received its message
						remaining := len(forwardings)
						for remaining > 0 {
							select {
							case err := <-errCh:
								Fail(fmt.Sprintf("target server error: %s", err))
							case <-done:
								remaining--
							case <-time.After(10 * time.Second):
								Fail("timed out waiting for target servers to finish")
							}
						}
					}

					It("works with multiple local port forwardings (-L)", func() {
						testMultipleTCPPortForwardings([]tcpForwardingSpec{
							{"-forward-tcp", 8100, 9100, "hello to remote 1", "hello from remote 1"},
							{"-forward-tcp", 8101, 9101, "hello to remote 2", "hello from remote 2"},
						})
					})

					It("works with multiple remote port forwardings (-R)", func() {
						testMultipleTCPPortForwardings([]tcpForwardingSpec{
							{"-reverse-tcp", 8200, 9200, "hello to local 1", "hello from local 1"},
							{"-reverse-tcp", 8201, 9201, "hello to local 2", "hello from local 2"},
						})
					})

					It("works with a mix of local and remote port forwardings", func() {
						testMultipleTCPPortForwardings([]tcpForwardingSpec{
							{"-forward-tcp", 8300, 9300, "hello to remote 1", "hello from remote 1"},
							{"-reverse-tcp", 8301, 9301, "hello to local 1", "hello from local 1"},
							{"-forward-tcp", 8302, 9302, "hello to remote 2", "hello from remote 2"},
							{"-reverse-tcp", 8303, 9303, "hello to local 2", "hello from local 2"},
						})
					})
				})
			})

			Context("scp file transfer", func() {
				// scpRemoteURL builds a client connection URL with the remote path
				// appended after the '%' separator (':' is used for the port), e.g.
				// ssh3-testuser@127.0.0.1:4433/sshoq-tests%/home/ssh3-testuser/x.txt.
				// The connection URL is already part of the string, so scp client
				// args are built manually instead of via getClientArgs (which
				// appends a bare connection URL as the last argument).
				scpRemoteURL := func(bind, remotePath string) string {
					return fmt.Sprintf("%s@%s%s%%%s", username, bind, DEFAULT_URL_PATH, remotePath)
				}

				It("uploads a single file with -scp", func() {
					localFile := filepath.Join(GinkgoT().TempDir(), "localfile.txt")
					err := os.WriteFile(localFile, []byte("hello from scp upload"), 0644)
					Expect(err).ToNot(HaveOccurred())

					remoteFile := fmt.Sprintf("/home/%s/scp-uploaded-%d.txt", username, time.Now().UnixNano())
					defer os.RemoveAll(remoteFile)

					clientArgs := []string{
						"-v", "-insecure", "-i", rsaPrivKeyPath,
						"-scp",
						localFile,
						scpRemoteURL(serverBind, remoteFile),
					}
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Uploaded .*localfile.txt"))

					content, err := os.ReadFile(remoteFile)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(content)).To(Equal("hello from scp upload"))
				})

				It("uploads a directory recursively with -scp -r", func() {
					localDir := filepath.Join(GinkgoT().TempDir(), "scp-folder")
					err := os.MkdirAll(filepath.Join(localDir, "sub"), 0755)
					Expect(err).ToNot(HaveOccurred())
					err = os.WriteFile(filepath.Join(localDir, "a.txt"), []byte("alpha"), 0644)
					Expect(err).ToNot(HaveOccurred())
					err = os.WriteFile(filepath.Join(localDir, "sub", "b.txt"), []byte("beta"), 0644)
					Expect(err).ToNot(HaveOccurred())

					// the trailing '/' makes the remote folder be copied into the
					// destination under its own basename, like scp -r
					remoteParent := fmt.Sprintf("/home/%s/scp-dest-%d/", username, time.Now().UnixNano())
					defer os.RemoveAll(remoteParent)

					clientArgs := []string{
						"-v", "-insecure", "-i", rsaPrivKeyPath,
						"-scp", "-r",
						localDir,
						scpRemoteURL(serverBind, remoteParent),
					}
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))

					content, err := os.ReadFile(filepath.Join(remoteParent, "scp-folder", "a.txt"))
					Expect(err).ToNot(HaveOccurred())
					Expect(string(content)).To(Equal("alpha"))
					content, err = os.ReadFile(filepath.Join(remoteParent, "scp-folder", "sub", "b.txt"))
					Expect(err).ToNot(HaveOccurred())
					Expect(string(content)).To(Equal("beta"))
				})

				It("downloads a single file with -scp", func() {
					// first place a remote file via an scp upload, then fetch it back
					localSrc := filepath.Join(GinkgoT().TempDir(), "src.txt")
					err := os.WriteFile(localSrc, []byte("round trip content"), 0644)
					Expect(err).ToNot(HaveOccurred())

					remoteFile := fmt.Sprintf("/home/%s/scp-roundtrip-%d.txt", username, time.Now().UnixNano())
					defer os.RemoveAll(remoteFile)

					uploadArgs := []string{
						"-v", "-insecure", "-i", rsaPrivKeyPath,
						"-scp",
						localSrc,
						scpRemoteURL(serverBind, remoteFile),
					}
					upSession, err := Start(exec.Command(ssh3Path, uploadArgs...), GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(upSession).Should(Exit(0))

					localDir := GinkgoT().TempDir()
					// for a download, the remote URL comes first and the local
					// destination second, so the args are built manually
					clientArgs := []string{
						"-v", "-insecure", "-i", rsaPrivKeyPath,
						"-scp",
						scpRemoteURL(serverBind, remoteFile),
						localDir,
					}
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Downloaded .*scp-roundtrip-"))

					// the downloaded file keeps the remote basename, like scp
					content, err := os.ReadFile(filepath.Join(localDir, filepath.Base(remoteFile)))
					Expect(err).ToNot(HaveOccurred())
					Expect(string(content)).To(Equal("round trip content"))
				})

				It("downloads a directory recursively with -scp -r", func() {
					// create a remote directory tree via an scp upload, then fetch it back
					localSrcDir := filepath.Join(GinkgoT().TempDir(), "remote-folder")
					err := os.MkdirAll(filepath.Join(localSrcDir, "nested"), 0755)
					Expect(err).ToNot(HaveOccurred())
					err = os.WriteFile(filepath.Join(localSrcDir, "one.txt"), []byte("first"), 0644)
					Expect(err).ToNot(HaveOccurred())
					err = os.WriteFile(filepath.Join(localSrcDir, "nested", "two.txt"), []byte("second"), 0644)
					Expect(err).ToNot(HaveOccurred())

					remoteParent := fmt.Sprintf("/home/%s/scp-rdest-%d/", username, time.Now().UnixNano())
					defer os.RemoveAll(remoteParent)

					uploadArgs := []string{
						"-v", "-insecure", "-i", rsaPrivKeyPath,
						"-scp", "-r",
						localSrcDir,
						scpRemoteURL(serverBind, remoteParent),
					}
					upSession, err := Start(exec.Command(ssh3Path, uploadArgs...), GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(upSession).Should(Exit(0))

					localDir := GinkgoT().TempDir()
					clientArgs := []string{
						"-v", "-insecure", "-i", rsaPrivKeyPath,
						"-scp", "-r",
						scpRemoteURL(serverBind, filepath.Join(remoteParent, "remote-folder")),
						localDir,
					}
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))

					content, err := os.ReadFile(filepath.Join(localDir, "remote-folder", "one.txt"))
					Expect(err).ToNot(HaveOccurred())
					Expect(string(content)).To(Equal("first"))
					content, err = os.ReadFile(filepath.Join(localDir, "remote-folder", "nested", "two.txt"))
					Expect(err).ToNot(HaveOccurred())
					Expect(string(content)).To(Equal("second"))
				})

				It("returns a useful error when SFTP is disabled on the server", func() {
					localFile := filepath.Join(GinkgoT().TempDir(), "localfile.txt")
					err := os.WriteFile(localFile, []byte("x"), 0644)
					Expect(err).ToNot(HaveOccurred())

					remoteFile := fmt.Sprintf("/home/%s/scp-disabled-%d.txt", username, time.Now().UnixNano())
					clientArgs := []string{
						"-v", "-insecure", "-i", rsaPrivKeyPath,
						"-scp",
						localFile,
						scpRemoteURL(serverBindSFTPDisabled, remoteFile),
					}
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))
					Eventually(session.Err).Should(Say("could not open sftp channel: .*SFTP is disabled on the server"))
				})
			})

			// It checks the client with the -forward-udp or -reverse-udp forwarding options.
			// As forward-tcp, a TCP socket is indeed well open on the client and is forwarded
			// through the SSH3 connection towards the specified remote IP and port at server´s reach.
			// When reverse-tcp is specified, a UDP socket is open on the server and forwarded through
			// the SSH3 connection towards the specified remote IP and port at client's reach.
			// As the server and the client are run on the same machine the same test can be reused
			// for both cases.
			Context("UDP port forwarding", func() {
				testUDPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.UDPAddr, messageFromClient, messageFromServer string, forwardingType string) {
					localIP := "[::1]"
					localIPWithoutBrackets := "::1"
					if remoteAddr.IP.To4() != nil {
						localIP = "127.0.0.1"
						localIPWithoutBrackets = localIP
					}
					serverStarted := make(chan struct{})
					done := make(chan struct{})
					// Start a UDP server on the specified remote IP and port
					go func() {
						defer close(done)
						defer close(serverStarted)
						defer GinkgoRecover()
						conn, err := net.ListenUDP("udp", remoteAddr)
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()

						serverStarted <- struct{}{}

						buffer := make([]byte, 2*len(messageFromClient))
						n, clientAddr, err := conn.ReadFromUDP(buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(clientAddr.IP.String()).To(Equal(localIPWithoutBrackets))
						Expect(string(buffer[:n])).To(Equal(messageFromClient))

						// Send message to client
						_, err = conn.WriteToUDP([]byte(messageFromServer), clientAddr)
						Expect(err).ToNot(HaveOccurred())
					}()

					Eventually(serverStarted).Should(Receive())
					// Execute the client with UDP port forwarding

					additionalArgs := []string{}
					if proxyJump {
						additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
					}
					if remoteAddr.IP.To4() == nil {
						// with an IPv6 remote address, also bind the local forward socket on
						// the IPv6 loopback (4-parts syntax: bindAddress@localPort@remoteIP@remotePort)
						additionalArgs = append(additionalArgs, forwardingType, fmt.Sprintf("::1@%d@%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
					} else {
						additionalArgs = append(additionalArgs, forwardingType, fmt.Sprintf("%d@%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
					}
					clientArgs := getClientArgs(rsaPrivKeyPath, additionalArgs...)
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					defer session.Terminate()

					// Wait for some time to ensure that the client has established the forwarding
					time.Sleep(2 * time.Second)

					// if the remote addr is IPv4 (resp. IPv6), ssh3 listens on the IPv4 (resp. IPv6) loopback
					// Try to connect to the local forwarded port
					localAddr := fmt.Sprintf("%s:%d", localIP, localPort)

					var conn net.Conn
					Eventually(func() error {
						var err error
						conn, err = net.Dial("udp", localAddr)
						return err
					}).ShouldNot(HaveOccurred())
					defer conn.Close()

					// Send message from client
					n, err := conn.Write([]byte(messageFromClient))
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromClient)))

					// Read message from server
					buffer := make([]byte, 2*len(messageFromServer))
					conn.SetReadDeadline(time.Now().Add(1 * time.Second))
					n, err = conn.Read(buffer)
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(string(buffer[:n])).To(Equal(messageFromServer))

					// wait for the remote goroutine to finish: its socket is bound on the
					// shared remote port, and the next sub-test reuses the same port
					Eventually(done).Should(BeClosed())
				}

				It("works with small messages", func() {
					testUDPPortForwarding(8080, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-forward-udp")
					testUDPPortForwarding(8090, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-reverse-udp")
				})

				It("works through proxy jump", func() {
					testUDPPortForwarding(8080, true, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-forward-udp")
					testUDPPortForwarding(8091, true, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-reverse-udp")
				})

				// Due to current quic-go limitations, the max datagram size is limited to 1200, whatever the real MTU is,
				// so right now we test for 1150 messages and nothing more
				It("works with messages of 1150 bytes", func() {
					rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
					messageFromClient := make([]byte, 1150)
					messageFromServer := make([]byte, 1150)
					n, err := rng.Read(messageFromClient)
					Expect(n).To(Equal(len(messageFromClient)))
					Expect(err).ToNot(HaveOccurred())
					n, err = rng.Read(messageFromServer)
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(err).ToNot(HaveOccurred())
					testUDPPortForwarding(8081, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer), "-forward-udp")
					testUDPPortForwarding(8092, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer), "-reverse-udp")
				})

				It("works with IPv6 addresses", func() {
					// Check whether IPv6 is available on the host
					addrs, err := net.InterfaceAddrs()
					Expect(err).ToNot(HaveOccurred())
					if !IPv6LoopbackAvailable(addrs) {
						Skip("IPv6 not available on this host")
					}
					testUDPPortForwarding(8082, false, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9090}, "hello from client", "hello from server", "-forward-udp")
					testUDPPortForwarding(8093, false, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9090}, "hello from client", "hello from server", "-reverse-udp")
				})

			})

			Context("Server behaviour", func() {
				It("Should not grand access to non-authorized identity", func() {
					clientArgs = append(getClientArgs(attackerPrivKeyPath), "echo", "Hello, World!")

					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit())
					Eventually(session).ShouldNot(Exit(0))
					Eventually(string(session.Wait().Err.Contents())).Should(ContainSubstring("Unauthorized"))
				})
			})
		})
	})
})
