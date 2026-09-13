package backup

import (
	"reflect"
	"testing"
)

func TestArchiveEntryNames(t *testing.T) {
	got, err := ArchiveEntryNames([]string{"/etc", "/var/www", "/home/data"})
	if err != nil || !reflect.DeepEqual(got, map[string]string{"/etc": "etc", "/var/www": "www", "/home/data": "data"}) {
		t.Errorf("distinct basenames: %v %v", got, err)
	}

	got, err = ArchiveEntryNames([]string{"/etc/mydir", "/var/lib/mydir", "/opt"})
	want := map[string]string{"/etc/mydir": "etc-mydir", "/var/lib/mydir": "var-lib-mydir", "/opt": "opt"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("duplicate basenames: %v %v; want %v", got, err, want)
	}

	if _, err := ArchiveEntryNames([]string{"/etc-mydir", "/etc/mydir", "/var/lib/mydir"}); err == nil {
		t.Error("expected an error when the prefixed name collides with another root")
	}
}

func TestEntryNamesWindows(t *testing.T) {
	names, err := ArchiveEntryNames([]string{`C:\`, `D:\data`, `E:\data`})
	if err != nil {
		t.Fatal(err)
	}
	if names[`C:\`] != "C" || names[`D:\data`] != "D-data" || names[`E:\data`] != "E-data" {
		t.Errorf("windows entry names %v", names)
	}
	single, err := ArchiveEntryNames([]string{`C:\Users`})
	if err != nil || single[`C:\Users`] != "Users" {
		t.Errorf("single windows path %v %v", single, err)
	}
	for in, want := range map[string]string{`C:\`: "C", "c:": "C", `D:/`: "D", "/": "root", "/etc": "etc", `C:\Users`: "Users"} {
		if got := entryBase(in); got != want {
			t.Errorf("entryBase(%q) = %q, want %q", in, got, want)
		}
	}
	if pathEntryName(`D:\data\x`) != "D-data-x" {
		t.Errorf("pathEntryName windows: %q", pathEntryName(`D:\data\x`))
	}
}
