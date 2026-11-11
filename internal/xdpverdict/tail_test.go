package xdpverdict

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTailHandlesCreationAppendRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 8)
	done := make(chan error, 1)
	go func() { done <- Tail(ctx, p, 10*time.Millisecond, func(v []byte) { got <- string(v) }) }()
	time.Sleep(40 * time.Millisecond)
	if err := os.WriteFile(p, []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	expect := func(want string) {
		t.Helper()
		select {
		case x := <-got:
			if x != want {
				t.Fatalf("got %q want %q", x, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %q", want)
		}
	}
	expect("first")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("sec")
	time.Sleep(30 * time.Millisecond)
	_, _ = f.WriteString("ond\n")
	_ = f.Close()
	expect("second")
	if err = os.Rename(p, p+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, []byte("rotated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	expect("rotated")
	if err = os.WriteFile(p, []byte("new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	expect("new")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTailSkipsExistingContentOnStartup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(p, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 2)
	done := make(chan error, 1)
	go func() { done <- Tail(ctx, p, 10*time.Millisecond, func(v []byte) { got <- string(v) }) }()
	time.Sleep(70 * time.Millisecond)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("new\n")
	_ = f.Close()
	select {
	case x := <-got:
		if x != "new" {
			t.Fatalf("replayed stale line %q", x)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new line missing")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
