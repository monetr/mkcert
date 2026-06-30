// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// These tests live in package main on purpose. The behavior worth pinning down
// here (filename math, env driven config, key generation) is all unexported, so
// an external _test package cant reach it. None of these tests touch a real
// trust store, they only ever read the environment or write into t.TempDir().

func TestMain(m *testing.M) {
	// The commands under test log a lot of human friendly chatter to the
	// default logger. We dont care about any of it while testing, so send it
	// to the void to keep the test output readable.
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func TestStoreEnabled(t *testing.T) {
	t.Run("empty TRUST_STORES enables everything", func(t *testing.T) {
		// When the env var is unset we want every store to be considered
		// enabled, that is the autodetect default.
		t.Setenv("TRUST_STORES", "")
		for _, store := range []string{"system", "nss", "java"} {
			if !storeEnabled(store) {
				t.Errorf("should enable %q when TRUST_STORES is empty", store)
			}
		}
	})

	t.Run("only the listed stores are enabled", func(t *testing.T) {
		t.Setenv("TRUST_STORES", "system,java")
		if !storeEnabled("system") {
			t.Error("should enable system because it is in the list")
		}
		if !storeEnabled("java") {
			t.Error("should enable java because it is in the list")
		}
		if storeEnabled("nss") {
			t.Error("should not enable nss because it is not in the list")
		}
	})

	t.Run("whitespace is not trimmed", func(t *testing.T) {
		// NOTE This documents a real gotcha. The list is split on commas and
		// compared exactly, so "system, nss" leaves " nss" which never matches
		// the bare "nss" name. If we ever start trimming, this test should
		// flip and tell us we changed the contract.
		t.Setenv("TRUST_STORES", "system, nss")
		if !storeEnabled("system") {
			t.Error("should still enable system, it has no surrounding space")
		}
		if storeEnabled("nss") {
			t.Error("should not match \" nss\" because the leading space is not trimmed")
		}
	})
}

func TestGetCAROOT(t *testing.T) {
	t.Run("CAROOT env overrides everything", func(t *testing.T) {
		// The CAROOT env var is the escape hatch for maintaining multiple
		// CAs, so it has to win over every platform specific default.
		dir := t.TempDir()
		t.Setenv("CAROOT", dir)
		if got := getCAROOT(); got != dir {
			t.Errorf("should return the CAROOT override, got %q want %q", got, dir)
		}
	})

	t.Run("falls back to XDG_DATA_HOME", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("XDG_DATA_HOME is not consulted on windows")
		}
		t.Setenv("CAROOT", "")
		dir := t.TempDir()
		t.Setenv("XDG_DATA_HOME", dir)
		want := filepath.Join(dir, "mkcert")
		if got := getCAROOT(); got != want {
			t.Errorf("should fall back to XDG_DATA_HOME, got %q want %q", got, want)
		}
	})

	t.Run("falls back to HOME on linux", func(t *testing.T) {
		// The default location is OS specific (darwin uses Library/Application
		// Support, windows uses LocalAppData) so we only assert the Unix path
		// on linux where we know what it should be.
		if runtime.GOOS != "linux" {
			t.Skipf("default path is OS specific, skipping on %s", runtime.GOOS)
		}
		t.Setenv("CAROOT", "")
		t.Setenv("XDG_DATA_HOME", "")
		home := t.TempDir()
		t.Setenv("HOME", home)
		want := filepath.Join(home, ".local", "share", "mkcert")
		if got := getCAROOT(); got != want {
			t.Errorf("should fall back to HOME/.local/share, got %q want %q", got, want)
		}
	})
}

func TestPathExists(t *testing.T) {
	t.Run("returns true for a path that exists", func(t *testing.T) {
		dir := t.TempDir()
		if !pathExists(dir) {
			t.Error("should return true for a directory that exists")
		}
	})

	t.Run("returns false for a path that does not exist", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		if pathExists(missing) {
			t.Error("should return false for a path that does not exist")
		}
	})
}

func TestBinaryExists(t *testing.T) {
	t.Run("returns false for a binary that is not on the PATH", func(t *testing.T) {
		if binaryExists("mkcert-no-such-binary-xyz") {
			t.Error("should return false for a binary that does not exist")
		}
	})

	t.Run("returns true for a binary on the PATH", func(t *testing.T) {
		// Windows resolves executables through PATHEXT and has no executable
		// bit, so this fake-script trick only works on the Unix like systems.
		if runtime.GOOS == "windows" {
			t.Skip("executable bit and PATHEXT handling differ on windows")
		}
		dir := t.TempDir()
		bin := filepath.Join(dir, "fakebin")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatalf("must be able to create a fake executable: %s", err)
		}
		// Point PATH at just our temp dir so the lookup is deterministic.
		t.Setenv("PATH", dir)
		if !binaryExists("fakebin") {
			t.Error("should find an executable that is on the PATH")
		}
	})
}
