// Package conformance starts the ubi-gs binary and drives it with a client built from the Python
// implementation's own protocol modules (client.py): login, the lobby, two players in a room, the
// match start, a rated result, friends, the ladder, the relay and IRC chat.
//
// It needs the Python ubi-gs and its requirements:
//
//	UBIGS_REF=/path/to/ubi-gs UBIGS_PYTHON=/path/to/venv/bin/python go test ./tests/conformance
package conformance

import (
	"bufio"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestConformance(t *testing.T) {
	ref := os.Getenv("UBIGS_REF")
	if ref == "" {
		t.Skip("set UBIGS_REF to the Python ubi-gs checkout (and UBIGS_PYTHON to its interpreter)")
	}
	if runtime.GOOS != "linux" {
		t.Skip("needs 127.0.0.x source addresses (Linux)")
	}
	python := os.Getenv("UBIGS_PYTHON")
	if python == "" {
		python = "python3"
	}
	bin := filepath.Join(t.TempDir(), "ubi-gs")
	build := exec.Command("go", "build", "-o", bin, "../../cmd/ubi-gs")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for attempt := 0; attempt < 5; attempt++ {
		offset := 20000 + rand.IntN(3000)*10
		gsconnect := offset + 7777 + 9
		relayMin := offset + 7777 + 100
		cmd := exec.Command(bin, "--bind", "127.0.0.1", "--db", ":memory:", "--port-offset", fmt.Sprint(offset),
			"--gsconnect-port", fmt.Sprint(gsconnect), "--relay-ports", fmt.Sprintf("%d-%d", relayMin, relayMin+50),
			"--no-firewall-check", "--max-new-accounts-per-ip-hour", "0")
		cmd.Env = os.Environ()
		stdout, _ := cmd.StdoutPipe()
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		ready := make(chan bool, 1)
		var log strings.Builder
		go func() {
			sc := bufio.NewScanner(stdout)
			sent := false
			for sc.Scan() {
				log.WriteString(sc.Text() + "\n")
				if !sent && strings.Contains(sc.Text(), "all services started") {
					ready <- true
					sent = true
				}
			}
			if !sent {
				ready <- false
			}
		}()
		select {
		case ok := <-ready:
			if !ok {
				cmd.Wait()
				if cmd.ProcessState.ExitCode() == 2 {
					continue // a port was taken: try others
				}
				t.Fatalf("server didn't start:\n%s", log.String())
			}
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			t.Fatal("server didn't start in time")
		}
		client := exec.Command(python, "-u", "client.py", ref, fmt.Sprint(offset), fmt.Sprint(gsconnect))
		out, err := client.CombinedOutput()
		t.Logf("client:\n%s", out)
		// a clean shutdown on SIGTERM
		cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case werr := <-done:
			if werr != nil {
				t.Errorf("server exit: %v", werr)
			}
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			t.Error("server didn't stop on SIGTERM")
		}
		if err != nil {
			t.Fatalf("conformance client failed: %v\nserver log:\n%s", err, log.String())
		}
		if !strings.Contains(log.String(), "stopped") {
			t.Errorf("no clean stop in the log:\n%s", log.String())
		}
		return
	}
	t.Fatal("no free ports")
}
