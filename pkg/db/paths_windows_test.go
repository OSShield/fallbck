package db

import (
	"strings"
	"testing"
)

func TestValidateWindowsPaths(t *testing.T) {
	got, err := ValidateBackupPathsFor("windows", []string{" C:/Users/ ", `c:\users`, `D:\data\..\data\.\logs`, `\\?\ignored`[:0]})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != `C:\Users|D:\data\logs` {
		t.Errorf("cleaned %v", got)
	}
	bad := [][]string{
		{"Users"}, {`\\server\share`}, {"/etc"}, {`C:relative`},
		{`C:\`, `C:\Users`}, {`D:\data`, `d:\DATA\logs`},
	}
	for _, in := range bad {
		if _, err := ValidateBackupPathsFor("windows", in); err == nil {
			t.Errorf("%v: expected an error", in)
		}
	}
	if _, err := ValidateBackupPathsFor("windows", []string{`C:\`}); err != nil {
		t.Errorf("volume root: %v", err)
	}
	if _, err := ValidateBackupPathsFor("linux", []string{"/etc", "/var/lib"}); err != nil {
		t.Errorf("linux paths: %v", err)
	}
	if _, err := ValidateBackupPathsFor("linux", []string{`C:\Users`}); err == nil {
		t.Error("windows path on a linux agent must fail")
	}
}
