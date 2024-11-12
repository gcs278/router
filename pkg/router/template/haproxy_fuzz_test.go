package templaterouter

import (
	"fmt"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/library-go/pkg/route/validation"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"text/template"
	"time"
	"unicode"
)

const haproxyBinary = "/home/gspence/src/haproxy.org/haproxy-2.6/haproxy-2.6.14" // Path to HAProxy binary
const haproxyConfTemplate = `
global
    maxconn 256
    pidfile /tmp/haproxy.pid

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend local-in
    bind *:8080
    default_backend servers

backend servers
    http-request replace-path ^{{ .Path }}(.*)$ '/foo\1'
    server server1 127.0.0.1:8081 maxconn 32
`

const haproxyConfTemplateFixed = `
global
    maxconn 256
    pidfile /tmp/haproxy.pid

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend local-in
    bind *:8080
    default_backend servers

backend servers
    http-request replace-path '^{{ processRewritePath .Path }}(.*)$' '/foo'
    server server1 127.0.0.1:8081 maxconn 32
`

const haproxyConfTemplateQuoted = `
global
    maxconn 256
    pidfile /tmp/haproxy.pid

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend fixed
    bind *:8080
	monitor-uri /health
    default_backend fixed-servers

backend fixed-servers
    http-request replace-path '^{{ processRewritePathQuotesOnly .Path }}(.*)$' '/rewrite\1'
    server server1 127.0.0.1:8081 maxconn 32

frontend not-fixed
    bind *:8082
    default_backend not-fixed-servers

backend not-fixed-servers
    http-request replace-path ^{{ .Path }}(.*)$ '/rewrite\1'
    server server1 127.0.0.1:8083 maxconn 32
`

const templatePath = "../../../images/router/haproxy/conf/haproxy-config.template"

// createHAProxyConfig generates a temporary HAProxy config file with a fuzzed http-request replace-path directive.
func createHAProxyConfig(replacePathDirective, haproxyConfTemplate string) (string, error) {
	// Create a temporary file for the HAProxy config
	tmpFile, err := ioutil.TempFile("", "haproxy-*.cfg")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()
	fixedTemplate, err := template.New("config").Funcs(helperFunctions).Parse(haproxyConfTemplate)
	if err != nil {
		return "", fmt.Errorf("error parsing fixedTemplate for file %s: %v", tmpFile.Name(), err)
	}
	data := struct {
		Path string
	}{
		Path: replacePathDirective,
	}
	if err := fixedTemplate.Execute(tmpFile, data); err != nil {
		return "", fmt.Errorf("error executing fixedTemplate for file %s: %v", tmpFile.Name(), err)
	}

	return tmpFile.Name(), nil
}

func validateHAProxyConfig(configFile string) error {
	cmd := exec.Command(haproxyBinary, "-c", "-f", configFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		data, _ := os.ReadFile(configFile)
		return fmt.Errorf("configuration validation failed: %s, config file: %s", output, data)
	}

	return nil
}

func startHAProxyConfig(t *testing.T, configFile string) (error, *exec.Cmd) {
	// Clean up old haproxy processes that might have been left by other tests.
	procName := filepath.Base(haproxyBinary)
	if pids, err := findProcesses(procName); err != nil {
		t.Fatalf("Error finding processes: %v", err)
	} else if len(pids) > 0 {
		t.Logf("Killing processes: %v", pids)
		if err := killProcesses(pids); err != nil {
			t.Fatalf("Error killing %s processes: %v", procName, err)
		}
	}

	cmd := exec.Command(haproxyBinary, "-f", configFile)
	err := cmd.Start()
	if err != nil {
		data, _ := os.ReadFile(configFile)
		return fmt.Errorf("failed to start haproxy: %s", data), nil
	}

	if err := WaitForURLSuccess(t, "http://localhost:8080/health", 10*time.Second); err != nil {
		return err, nil
	}
	t.Logf("haproxy is healthy")

	return nil, cmd
}

// FuzzHAProxyReplacePath is a fuzz test that verifies HAProxy starts successfully with fuzzed replace-path values.
func FuzzHAProxyReplacePath(f *testing.F) {
	// Seed corpus with invalid replace-path examples
	f.Add(`"'"'`)
	f.Add(` `)
	f.Add(`\ `)
	f.Add(`\x0`)
	f.Add("/^*")
	f.Add(`"\"`)
	f.Add("/^+")
	f.Add("/$*")
	f.Add("/$+")
	f.Add("/foo")
	f.Add("/foo'")
	f.Add("/foo''")
	f.Add(`/foo\''`)
	f.Add(`/foo"`)
	f.Add(`/foo\"`)
	f.Add(`/#foo`)
	f.Add(`/#foo#`)
	f.Add(`/#foo[Z-a]`)
	f.Add(`/#foo[A-Z]`)
	f.Add(`/foo\`)
	f.Add(`/foo\\`)
	f.Add(`/[foo`)
	f.Add(`/foo]`)
	f.Add(`/foo[0-9`)
	f.Add(`/[A-Z`)
	f.Add(`/[A-Z]+(foo)`)
	f.Add(`/[^a-zA-Z]foo`)
	f.Add(`/foo|bar|baz`)
	f.Add(`/foo{3,}`)
	f.Add(`/foo{3,5`)
	f.Add(`/foo*bar?`)
	f.Add(`/(foo)(bar`)
	f.Add(`/(foo|bar`)
	f.Add(`/foo\(`)
	f.Add(`/foo\)`)
	f.Add(`/foo.*`)

	// Single and double quotes
	f.Add(`/'foo'`)
	f.Add(`/"foo"`)
	f.Add(`/'foo"`)
	f.Add(`/foo'bar"`)
	f.Add(`/foo"bar'`)

	// Comments
	f.Add(`/# This is a comment`)
	f.Add(`/foo # inline comment`)
	f.Add(`/#foo\'' # another comment`)

	// Invalid escape sequences
	f.Add(`/foo\z`)
	f.Add(`/foo\Q`)
	f.Add(`/foo\A`)
	f.Add(`/foo\1`)
	f.Add(`/foo\nbar`)
	f.Add(`/foo\rbar`)

	// Misplaced or empty patterns
	f.Add(`[]`)
	f.Add(`{}`)
	f.Add(`()`)
	f.Add(`|foo|bar`)
	f.Add(`*foo`)
	f.Add(`+foo`)

	// Complex and invalid combinations
	f.Add(`(?:foo|bar`)
	f.Add(`(?=foo`)
	f.Add(`(?!foo`)
	f.Add(`(?<=foo`)
	f.Add(`(?<!foo`)
	f.Add(`[a-z]{3,2}`)
	f.Add(`(?P<name>foo)`)

	f.Fuzz(func(t *testing.T, routePath string) {
		if !strings.HasPrefix(routePath, "/") {
			routePath = "/" + routePath // Add "/" if it’s missing
		}

		t.Logf("fuzz testing: %s\n", routePath)

		for _, r := range routePath {
			if !unicode.IsPrint(r) {
				t.Skip("Skipping test because variable contains non-Unicode characters")
			}
		}
		for i := 0; i < len(routePath); i++ {
			if routePath[i] < 32 || routePath[i] > 126 { // ASCII printable range is 32–126
				t.Skipf("Skipping input containing non-ASCII character:%q", routePath[i])
			}
		}
		if strings.ContainsAny(routePath, `\x00`) {
			// Figure this out later...
			t.Skipf("Skipping input containing null character:%q", routePath)
		}
		///////////////////////////////
		// Pick function here...
		/////////////////////////////

		// This is the total sanitation approach (just escape everything like we should have done in the beginning!)
		//sanitizeConfigApproach(t, routePath)

		// This is the approach of trying to reject everything in the API.
		//apiRejectionValidationApproach(t, routePath)

		// This is the 'just quote it' approach (partial sanitization). This function proves whether our update is compatible or not.
		//quoteConfigCompatibilityCheck(t, routePath)

		// This is the limited API rejection approach to appease/close the current bugs (spaces and #) to buy us some time.
		apiRejectionLimitedApproach(t, routePath)
	})
}

// This is a different approach. We try to reject a subset of characters to appease the bugs coming in, while we
// ensure what we are rejecting isn't already a valid approach.
func apiRejectionLimitedApproach(t *testing.T, routePath string) {
	// Exceptions in which that we can break compatibility.
	if strings.Contains(routePath, ` `) && strings.Contains(routePath, `#`) {
		t.Skipf("Skipping path that contains space AND # even though it'll break compatilbity because this is very RISKY thing to allow")
	}

	// TODO: You can vendor your library-go function here and call it to test that it is compatible
	//route := &routev1.Route{
	//	ObjectMeta: metav1.ObjectMeta{
	//		Annotations: map[string]string{
	//			// This just needs to be present, value doesn't matter.
	//			"haproxy.router.openshift.io/rewrite-target": "/foo",
	//		},
	//	},
	//	Spec: routev1.RouteSpec{
	//		Path: routePath,
	//	},
	//}
	//
	//// We just skip the test (success) if it is validated out
	//if errs := validation.ValidatePathWithRewriteTargetAnnotation(route, nil); len(errs) != 0 {

	// Here we do our "validation" and if we reject something, we want to ensure that
	// HAProxy actually fails. If it doesn't fail, that means we rejected something valid.
	// TODO: this if statement is temporary and should be replaced by library-go call for "real" testing.
	if !fakeSimpleValidation(routePath) {
		// Create a HAProxy config file with the fuzzed replace-path directive
		configFile, err := createHAProxyConfig(routePath, haproxyConfTemplate)
		if err != nil {
			t.Fatalf("failed to create HAProxy config: %v", err)
		}
		defer os.Remove(configFile) // Clean up config file

		// Start HAProxy with the fuzzed config
		if err := validateHAProxyConfig(configFile); err == nil {
			t.Errorf("Rejected, but HAProxy did NOT fail to start with replace-path %s: %v", routePath, err)
		}
	}
}

func fakeSimpleValidation(routePath string) bool {
	inDoubleQuotes := false
	inSingleQuotes := false
	for i := 0; i < len(routePath); i++ {
		c := routePath[i]
		if c == '"' {
			// Toggle double-quote state.
			if !inSingleQuotes {
				inDoubleQuotes = !inDoubleQuotes
			}
			continue
		}

		if c == '\'' {
			// Toggle single-quote state.
			if !inDoubleQuotes {
				inSingleQuotes = !inSingleQuotes
			}
			continue
		}

		if c == '\\' && i+1 < len(routePath) {
			// Skip the next escaped character.
			i++
			continue
		}

		if !inDoubleQuotes && !inSingleQuotes && (c == ' ' || c == '#') {
			// Reject if space or # is outside double or single quotes.
			return false
		}
	}
	return true
}

// this function resembles the approach we COULD take if we sanitized the HAProxy template.
// The problem with that it is not truly compatible (we are going to change behavior)
func sanitizeConfigApproach(t *testing.T, routePath string) {
	// Create a HAProxy config file with the fuzzed replace-path directive
	configFile, err := createHAProxyConfig(routePath, haproxyConfTemplateFixed)
	if err != nil {
		t.Fatalf("failed to create HAProxy config: %v", err)
	}
	defer os.Remove(configFile) // Clean up config file

	// Start HAProxy with the fuzzed config
	if err := validateHAProxyConfig(configFile); err != nil {
		t.Errorf("HAProxy failed to start with replace-path '%s': %v", routePath, err)
	}
}

func quoteConfigCompatibilityCheck(t *testing.T, routePath string) {
	// Because we can't parallelize HAProxy, we need to run it 1 at a time.
	// Force user to turn parallelization off.
	gomaxprocs := runtime.GOMAXPROCS(0)
	if gomaxprocs != 1 {
		t.Fatalf("GOMAXPROCS is %d, but expected 1. Please set GOMAXPROCS=1 in the environment.", gomaxprocs)
	}

	// Create a HAProxy config file with the fuzzed replace-path
	configFile, err := createHAProxyConfig(routePath, haproxyConfTemplateQuoted)
	if err != nil {
		t.Fatalf("failed to create HAProxy config: %v", err)
	}
	defer os.Remove(configFile) // Clean up config file

	if strings.Count(routePath, `'`) >= 2 || strings.Count(routePath, `"`) >= 2 {
		t.Skipf("skipping quotes for now...")
	}

	// first validate the config to make sure it will start
	if err := validateHAProxyConfig(configFile); err != nil {
		// If our config fails to start, that means HAProxy is failing on a syntax error.
		// For this, we don't care about compatibility...because it's already broken.
		// But we still care about things breaking HAProxy, such as Regexes, but we are not going to address that right now.
		// So lets skip it, but we should review these.
		t.Skipf("Skipping since HAProxy failed to validate with replace-path '%s' (aka it's already breaks HAProxy): %v", routePath, err)
	}

	// Start the test server for the quoted fix result
	serverQuoted, pathChanQuoted := StartTestServer(t, 8081)
	defer StopTestServer(t, serverQuoted)
	// Start the test server for the baseline (not-fixed) result
	serverBaseline, pathChanBaseline := StartTestServer(t, 8083)
	defer StopTestServer(t, serverBaseline)

	err, cmd := startHAProxyConfig(t, configFile)
	if err != nil {
		t.Errorf("HAProxy failed to start with replace-path '%s': %v", routePath, err)
	}
	defer func() {
		if err := cmd.Process.Signal(os.Kill); err != nil {
			t.Errorf("failed to send kill signal: %v", err)
		}
	}()
	// Simulate a request to haproxy for "fixed" rewrite path
	if err := WaitForURLSuccess(t, "http://localhost:8080"+routePath, 5*time.Second); err != nil {
		// If we can't get a response, it's probably a larger issue going on, we are just trying to check for compatibility.
		t.Skipf("failed to get response from HAProxy '%s': %v", "http://localhost:8080"+routePath, err)
	}

	quotedPath, err := WaitForPath(pathChanQuoted, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to get quoted path: %v", err)
	}
	t.Logf("recieved quoted: %s", quotedPath)

	// Simulate a request to haproxy for not-fixed (baseline) rewrite path
	if err := WaitForURLSuccess(t, "http://localhost:8082"+routePath, 5*time.Second); err != nil {
		// If we can't get a response, it's probably a larger issue going on, we are just trying to check for compatibility.
		t.Skipf("failed to get response from HAProxy '%s': %v", "http://localhost:8082"+routePath, err)
	}
	baselinePath, err := WaitForPath(pathChanBaseline, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to get baseline path: %v", err)
	}
	t.Logf("recieved baseline: %s", baselinePath)

	// Compare the quoted path with the baseline value to see if we've maintained compatibility
	if baselinePath != quotedPath {
		t.Fatalf("baseline path not equal to quoted path: %s vs %s", baselinePath, quotedPath)
	}
}

func apiRejectionValidationApproach(t *testing.T, routePath string) {
	route := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				// This just needs to be present, value doesn't matter.
				"haproxy.router.openshift.io/rewrite-target": "/foo",
			},
		},
		Spec: routev1.RouteSpec{
			Path: routePath,
		},
	}

	// We just skip the test (success) if it is validated out
	if errs := validation.ValidatePathWithRewriteTargetAnnotation(route, nil); len(errs) != 0 {
		t.Skipf("replace path value is rejected: %s", routePath)
	}
	if strings.ContainsAny(routePath, " \t\n\r") {
		t.Skip("Skipping test because variable contains whitespace")
	}

	// Create a HAProxy config file with the fuzzed replace-path directive
	configFile, err := createHAProxyConfig(routePath, haproxyConfTemplate)
	if err != nil {
		t.Fatalf("failed to create HAProxy config: %v", err)
	}
	defer os.Remove(configFile) // Clean up config file

	// Start HAProxy with the fuzzed config
	if err := validateHAProxyConfig(configFile); err != nil {
		t.Errorf("HAProxy failed to start with replace-path '%s': %v", routePath, err)
	}
}

func StartTestServer(t *testing.T, port int) (*http.Server, chan string) {
	pathChan := make(chan string, 100)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send the received path to the channel
		pathChan <- r.URL.Path
		// Print to the client
		fmt.Fprintf(w, "Received path: %s\n", r.URL.Path)
		//t.Logf("Received path: %s", r.URL.Path)
	})

	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: handler}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Fatalf("Server failed: %s\n", err)
		}
	}()

	return server, pathChan
}

func StopTestServer(t *testing.T, server *http.Server) {
	if err := server.Close(); err != nil {
		t.Errorf("Failed to stop server: %s\n", err)
	}
}

func WaitForURLSuccess(t *testing.T, url string, timeout time.Duration) error {
	start := time.Now()

	for {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}

		if resp != nil {
			resp.Body.Close()
		}

		if time.Since(start) > timeout {
			return fmt.Errorf("timeout reached while waiting for url to return 200: %s", url)
		}

		// Wait before retrying
		time.Sleep(100 * time.Millisecond)
	}
}

// findProcesses searches for processes that match the binary path prefix
func findProcesses(binaryPath string) ([]int, error) {
	cmd := exec.Command("ps", "-eo", "pid,comm")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	var pids []int

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pid := fields[0]
		command := fields[1]

		if strings.HasPrefix(command, binaryPath) {
			var pidInt int
			_, err := fmt.Sscanf(pid, "%d", &pidInt)
			if err == nil {
				pids = append(pids, pidInt)
			}
		}
	}

	return pids, nil
}

// killProcesses kills all processes with the given PIDs
func killProcesses(pids []int) error {
	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Printf("failed to find process with PID %d: %v\n", pid, err)
			continue
		}

		if err := process.Signal(syscall.SIGKILL); err != nil {
			fmt.Printf("failed to kill process with PID %d: %v\n", pid, err)
		} else {
			fmt.Printf("successfully killed process with PID %d\n", pid)
		}
	}
	return nil
}

func WaitForPath(pathChan chan string, timeout time.Duration) (string, error) {
	select {
	case path := <-pathChan:
		return path, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("timeout waiting for path")
	}
}
