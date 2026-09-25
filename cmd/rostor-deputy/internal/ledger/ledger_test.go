package ledger

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerPersistsAndIsCaseInsensitive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if l.Has("chattlab") {
		t.Fatal("empty ledger should not contain anything")
	}
	if err := l.Add("TestUser"); err != nil {
		t.Fatal(err)
	}
	if !l.Has("testuser") || !l.Has("TESTUSER") {
		t.Fatal("ledger lookup should be case-insensitive")
	}
	if err := l.Add("testuser"); err != nil {
		t.Fatal(err)
	}
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := l2.Usernames(); len(got) != 1 || got[0] != "testuser" {
		t.Fatalf("reloaded ledger = %v", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should be renamed away")
	}
}

func TestOpenMissingFileIsEmpty(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "nope", "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Usernames()) != 0 {
		t.Fatal("expected empty ledger")
	}
}

func TestOpenRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	_ = os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := Open(path); err == nil {
		t.Fatal("expected error for corrupt ledger")
	}
}
