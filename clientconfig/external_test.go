package clientconfig_test

import (
	"bfp/clientconfig"
	"bfp/session"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestExternalModuleAndActualKeygenCompatibility(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate source-only candidate")
	}
	moduleRoot := filepath.Dir(filepath.Dir(source))
	directory := t.TempDir()
	binary := filepath.Join(directory, "bfp")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/bfp")
	build.Dir = moduleRoot
	build.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		// No credential file exists at this point; compiler diagnostics are safe.
		t.Fatalf("build existing keygen command: %v\n%s", err, output)
	}
	keygenDir := filepath.Join(directory, "generated")
	keygen := exec.CommandContext(ctx, binary, "keygen", "-out", keygenDir)
	if err := keygen.Run(); err != nil {
		t.Fatal("invoke actual keygen command")
	}
	clientPath := filepath.Join(keygenDir, "client.json")
	file, err := clientconfig.Load(clientPath)
	if err != nil || file.Session.Server != "127.0.0.1:51880" || file.Session.TCPServer != "" || file.SOCKSListen != "127.0.0.1:1080" {
		t.Fatal("actual keygen client.json was not compatible")
	}
	client, err := session.NewClient(file.Session)
	if err != nil {
		t.Fatal("normal constructor rejected actual keygen credentials")
	}
	if err := client.Close(); err != nil {
		t.Fatal("close keygen client")
	}
	standalonePath := privateFixture(t, credentialBody(t, file.Session.Credentials))
	externalDir := filepath.Join(directory, "external")
	if err := os.Mkdir(externalDir, 0700); err != nil {
		t.Fatal("create external module")
	}
	goMod := fmt.Sprintf("module external.example/clientconfigcheck\n\ngo 1.26.0\n\nrequire (\n\tbfp v0.0.0\n\tgithub.com/flynn/noise v1.1.0\n\tgolang.org/x/crypto v0.57.0\n\tgolang.org/x/net v0.58.0\n\tgolang.org/x/sys v0.48.0\n)\n\nreplace bfp => %q\n", filepath.ToSlash(moduleRoot))
	if err := os.WriteFile(filepath.Join(externalDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal("write external module definition")
	}
	program := `package main
import (
    "bfp/clientconfig"
    "bfp/session"
    "fmt"
    "os"
)
func main() {
    if len(os.Args) != 3 { os.Exit(2) }
    file, err := clientconfig.Load(os.Args[1])
    if err != nil || file.SOCKSListen != "127.0.0.1:1080" { os.Exit(3) }
    client, err := session.NewClient(file.Session)
    if err != nil { os.Exit(4) }
    if client.Close() != nil { os.Exit(5) }
    credentials, err := clientconfig.LoadCredentials(os.Args[2])
    if err != nil { os.Exit(6) }
    client, err = session.NewClient(session.ClientConfig{Server:file.Session.Server, Credentials:credentials})
    if err != nil { os.Exit(7) }
    if client.Close() != nil { os.Exit(8) }
    fmt.Println("external-module-ok")
}
`
	if err := os.WriteFile(filepath.Join(externalDir, "main.go"), []byte(program), 0600); err != nil {
		t.Fatal("write external module program")
	}
	runArgs := []string{"run", "-mod=mod", ".", clientPath, standalonePath}
	runEnv := build.Env
	if _, err := os.Stat(filepath.Join(moduleRoot, "vendor", "modules.txt")); err == nil {
		if err := stageOfflineVendor(externalDir, moduleRoot); err != nil {
			t.Fatal("stage offline external module")
		}
		runArgs[1] = "-mod=vendor"
		runEnv = setEnvironment(runEnv, "GOFLAGS", "-mod=vendor")
	} else if !os.IsNotExist(err) {
		t.Fatal("inspect source vendor tree")
	}
	run := exec.CommandContext(ctx, "go", runArgs...)
	run.Dir = externalDir
	run.Env = runEnv
	output, err := run.CombinedOutput()
	if err != nil {
		// The test program only emits a fixed success marker. Do not print arbitrary
		// runtime output alongside credential-file arguments on failure.
		t.Fatalf("external module compilation/invocation failed: %v", err)
	}
	if strings.TrimSpace(string(output)) != "external-module-ok" {
		t.Fatal("external module did not emit the fixed success marker")
	}
}

func setEnvironment(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}

func stageOfflineVendor(externalDir, moduleRoot string) error {
	sourceVendor := filepath.Join(moduleRoot, "vendor")
	if err := copyTree(sourceVendor, filepath.Join(externalDir, "vendor"), func(path string, entry fs.DirEntry) bool {
		return filepath.ToSlash(path) != "modules.txt"
	}); err != nil {
		return err
	}
	if err := copyTree(moduleRoot, filepath.Join(externalDir, "vendor", "bfp"), func(path string, entry fs.DirEntry) bool {
		path = filepath.ToSlash(path)
		return path != "vendor" && !strings.HasPrefix(path, "vendor/") &&
			path != "verification" && !strings.HasPrefix(path, "verification/") &&
			path != "lab" && !strings.HasPrefix(path, "lab/")
	}); err != nil {
		return err
	}
	packages, err := sourcePackages(moduleRoot)
	if err != nil {
		return err
	}
	parentModules, err := os.ReadFile(filepath.Join(sourceVendor, "modules.txt"))
	if err != nil {
		return err
	}
	moduleRootSlash := filepath.ToSlash(moduleRoot)
	lines := []string{
		fmt.Sprintf("# bfp v0.0.0 => %s", moduleRootSlash),
		"## explicit; go 1.26.0",
	}
	lines = append(lines, packages...)
	lines = append(lines, strings.Split(strings.TrimRight(string(parentModules), "\r\n"), "\n")...)
	lines = append(lines, fmt.Sprintf("# bfp => %s", moduleRootSlash))
	return os.WriteFile(filepath.Join(externalDir, "vendor", "modules.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0600)
}

func copyTree(source, destination string, include func(string, fs.DirEntry) bool) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative != "." && !include(filepath.ToSlash(relative), entry) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := destination
		if relative != "." {
			target = filepath.Join(destination, relative)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular vendor entry %s", relative)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0600)
	})
}

func sourcePackages(moduleRoot string) ([]string, error) {
	set := make(map[string]struct{})
	err := filepath.WalkDir(moduleRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(moduleRoot, path)
		if err != nil {
			return err
		}
		relativeSlash := filepath.ToSlash(relative)
		if entry.IsDir() && relative != "." && (relativeSlash == "vendor" || strings.HasPrefix(relativeSlash, "vendor/") ||
			relativeSlash == "verification" || strings.HasPrefix(relativeSlash, "verification/") ||
			relativeSlash == "lab" || strings.HasPrefix(relativeSlash, "lab/")) {
			return filepath.SkipDir
		}
		if entry.IsDir() || filepath.Ext(relative) != ".go" {
			return nil
		}
		packageDir := filepath.ToSlash(filepath.Dir(relative))
		if packageDir == "." {
			set["bfp"] = struct{}{}
		} else {
			set["bfp/"+packageDir] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	packages := make([]string, 0, len(set))
	for packagePath := range set {
		packages = append(packages, packagePath)
	}
	sort.Strings(packages)
	return packages, nil
}
