package dbbackup

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// pg_dump (PostgreSQL) 16.4 (Debian 16.4-1.pgdg120+1)
	pgVersionRe = regexp.MustCompile(`\(PostgreSQL\)\s+(\d+)(?:\.(\d+))?`)
	// mysqldump  Ver 8.0.36 for Linux on x86_64 (MySQL Community Server - GPL)
	mysqlVerRe = regexp.MustCompile(`Ver\s+(\d+)\.(\d+)\.(\d+)`)
	// mariadb-dump  Ver 10.19 Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)
	mariaDistribRe = regexp.MustCompile(`Distrib\s+(\d+)\.(\d+)\.(\d+)`)
	// /usr/bin/mariadb-dump from 11.4.12-MariaDB, client 10.19 for Linux (x86_64)
	mariaFromRe = regexp.MustCompile(`from\s+(\d+)\.(\d+)\.(\d+)-MariaDB`)
	// mongodump version: 100.9.4  /  mongodump version: r4.2.24
	mongoVerRe = regexp.MustCompile(`version:\s+r?(\d+)\.(\d+)(?:\.(\d+))?`)
	// generic fallback
	anyVerRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)
)

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// parsePGVersion parses a PostgreSQL tool --version line
func parsePGVersion(line string) (major, minor int, ok bool) {
	m := pgVersionRe.FindStringSubmatch(line)
	if m == nil {
		return 0, 0, false
	}
	return atoi(m[1]), atoi(m[2]), true
}

// parseMySQLVersion parses a mysqldump/mariadb-dump --version line
func parseMySQLVersion(line string) (b Binary, ok bool) {
	for _, re := range []*regexp.Regexp{mariaDistribRe, mariaFromRe} {
		if m := re.FindStringSubmatch(line); m != nil {
			return Binary{Version: m[1] + "." + m[2] + "." + m[3], Major: atoi(m[1]), Minor: atoi(m[2]), Patch: atoi(m[3]), Flavor: "mariadb"}, true
		}
	}
	if m := mysqlVerRe.FindStringSubmatch(line); m != nil {
		flavor := "mysql"
		if strings.Contains(strings.ToLower(line), "mariadb") {
			flavor = "mariadb"
		}
		return Binary{Version: m[1] + "." + m[2] + "." + m[3], Major: atoi(m[1]), Minor: atoi(m[2]), Patch: atoi(m[3]), Flavor: flavor}, true
	}
	return Binary{}, false
}

// parseMongoVersion parses a mongodump --version line
func parseMongoVersion(line string) (b Binary, ok bool) {
	m := mongoVerRe.FindStringSubmatch(line)
	if m == nil {
		return Binary{}, false
	}
	return Binary{Version: strings.TrimPrefix(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), "r"), Major: atoi(m[1]), Minor: atoi(m[2]), Patch: atoi(m[3])}, true
}

// parseServerVersion parses "16.4", "8.0.36", "11.4.2-MariaDB-ubu2404" into a number
// major*10000 + minor*100 + patch
func parseServerVersion(s string) (major, minor, patch int) {
	m := anyVerRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, 0
	}
	return atoi(m[1]), atoi(m[2]), atoi(m[3])
}

func versionNum(major, minor, patch int) int {
	return major*10000 + minor*100 + patch
}

// versionAtLeast compares a Binary's version with major.minor.patch
func (b Binary) versionAtLeast(major, minor, patch int) bool {
	return versionNum(b.Major, b.Minor, b.Patch) >= versionNum(major, minor, patch)
}
