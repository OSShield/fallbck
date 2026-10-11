// Package pbstest is a minimal fake Proxmox Backup Server for tests: it accepts the
// backup-protocol upgrade over TLS and implements the session endpoints gopbs uses
// (dynamic index create/append/close, chunk and blob upload, previous, finish).
package pbstest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// Index is a dynamic index written during a session
type Index struct {
	Name       string
	Digests    []string
	Offsets    []uint64
	Closed     bool
	Size       uint64
	ChunkCount uint64
}

// Server is the fake PBS
type Server struct {
	t           *testing.T
	ln          net.Listener
	fingerprint string
	url         string

	// ExpectAuthorization, when set, is the exact Authorization header required on the
	// upgrade request; anything else is answered 401 like PBS (minus its 3 s delay).
	ExpectAuthorization string
	// FailUpgrade, when non-zero, answers every upgrade with this status
	FailUpgrade int

	mu       sync.Mutex
	upgrades []*http.Request
	nextWID  uint64
	indexes  map[uint64]*Index
	chunks   map[string]int // digest -> encoded size
	known    map[string]bool
	blobs    map[string][]byte // file name -> encoded blob
	finished int
}

// New starts a fake PBS on 127.0.0.1 with a self-signed certificate
func New(t *testing.T) *Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake-pbs"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	s := &Server{
		t:           t,
		ln:          ln,
		fingerprint: strings.Join(parts, ":"),
		url:         "https://" + ln.Addr().String(),
		nextWID:     1,
		indexes:     map[uint64]*Index{},
		chunks:      map[string]int{},
		known:       map[string]bool{},
		blobs:       map[string][]byte{},
	}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// URL is the https endpoint (host:port of the listener)
func (s *Server) URL() string { return s.url }

// Fingerprint is the SHA-256 of the certificate as colon-separated hex
func (s *Server) Fingerprint() string { return s.fingerprint }

// Upgrades returns the upgrade requests received so far
func (s *Server) Upgrades() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.upgrades...)
}

// Finished reports how many sessions called /finish
func (s *Server) Finished() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finished
}

// Indexes returns the indexes by archive name
func (s *Server) Indexes() map[string]*Index {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]*Index{}
	for _, idx := range s.indexes {
		copied := *idx
		out[idx.Name] = &copied
	}
	return out
}

// Blobs returns the uploaded blob names
func (s *Server) Blobs() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range s.blobs {
		out[k] = v
	}
	return out
}

// ChunkCount is the number of distinct chunks uploaded
func (s *Server) ChunkCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.chunks)
}

func (s *Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.upgrades = append(s.upgrades, req)
	fail, expect := s.FailUpgrade, s.ExpectAuthorization
	s.mu.Unlock()

	switch {
	case fail != 0:
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 7\r\nConnection: close\r\n\r\nrefused", fail, http.StatusText(fail))
		return
	case expect != "" && req.Header.Get("Authorization") != expect:
		fmt.Fprintf(conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 21\r\nConnection: close\r\n\r\nauthentication failed")
		return
	case req.Header.Get("Upgrade") != "proxmox-backup-protocol-v1" || req.URL.Query().Get("store") == "":
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad upgrade")
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: proxmox-backup-protocol-v1\r\nConnection: Upgrade\r\n\r\n")
	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(s.handleH2)})
}

func httpError(w http.ResponseWriter, code int, format string, args ...any) {
	w.WriteHeader(code)
	fmt.Fprintf(w, format, args...)
}

func (s *Server) handleH2(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpError(w, 500, "body: %v", err)
		return
	}
	q := r.URL.Query()

	switch r.Method + " " + r.URL.Path {
	case "POST /dynamic_index":
		name := q.Get("archive-name")
		if name == "" || !strings.HasSuffix(name, ".didx") {
			httpError(w, 400, "wrong archive extension")
			return
		}
		s.mu.Lock()
		wid := s.nextWID
		s.nextWID++
		s.indexes[wid] = &Index{Name: name}
		s.mu.Unlock()
		fmt.Fprintf(w, `{"data":%d}`, wid)

	case "PUT /dynamic_index":
		var in struct {
			WID     uint64   `json:"wid"`
			Digests []string `json:"digest-list"`
			Offsets []uint64 `json:"offset-list"`
		}
		if err := json.Unmarshal(body, &in); err != nil || len(in.Digests) != len(in.Offsets) {
			httpError(w, 400, "bad append body")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		idx, ok := s.indexes[in.WID]
		if !ok || idx.Closed {
			httpError(w, 400, "unknown or closed wid %d", in.WID)
			return
		}
		for _, d := range in.Digests {
			if !s.known[d] {
				httpError(w, 400, "no such chunk %s", d)
				return
			}
		}
		idx.Digests = append(idx.Digests, in.Digests...)
		idx.Offsets = append(idx.Offsets, in.Offsets...)

	case "POST /dynamic_close":
		wid, _ := strconv.ParseUint(q.Get("wid"), 10, 64)
		size, _ := strconv.ParseUint(q.Get("size"), 10, 64)
		count, _ := strconv.ParseUint(q.Get("chunk-count"), 10, 64)
		s.mu.Lock()
		defer s.mu.Unlock()
		idx, ok := s.indexes[wid]
		if !ok || idx.Closed {
			httpError(w, 400, "unknown or closed wid %d", wid)
			return
		}
		if uint64(len(idx.Digests)) != count {
			httpError(w, 400, "chunk-count %d, appended %d", count, len(idx.Digests))
			return
		}
		idx.Closed, idx.Size, idx.ChunkCount = true, size, count

	case "POST /dynamic_chunk":
		digest := q.Get("digest")
		if enc, _ := strconv.Atoi(q.Get("encoded-size")); enc != len(body) || len(digest) != 64 {
			httpError(w, 400, "bad chunk upload")
			return
		}
		if _, err := hex.DecodeString(digest); err != nil {
			httpError(w, 400, "bad digest")
			return
		}
		s.mu.Lock()
		s.chunks[digest] = len(body)
		s.known[digest] = true
		s.mu.Unlock()

	case "POST /blob":
		if enc, _ := strconv.Atoi(q.Get("encoded-size")); enc != len(body) {
			httpError(w, 400, "encoded-size %d, body %d", enc, len(body))
			return
		}
		s.mu.Lock()
		s.blobs[q.Get("file-name")] = append([]byte(nil), body...)
		s.mu.Unlock()

	case "GET /previous":
		// The latest closed index of that name (an earlier session) is the previous
		// snapshot's; like PBS, handing it out registers its chunks as known
		name := q.Get("archive-name")
		s.mu.Lock()
		var found *Index
		var foundWID uint64
		for wid, idx := range s.indexes {
			if idx.Name == name && idx.Closed && (found == nil || wid > foundWID) {
				found, foundWID = idx, wid
			}
		}
		var didx []byte
		if found != nil {
			didx = make([]byte, 4096, 4096+40*len(found.Digests))
			copy(didx, []byte{28, 145, 78, 165, 25, 186, 179, 205})
			for i, d := range found.Digests {
				end := found.Size
				if i+1 < len(found.Offsets) {
					end = found.Offsets[i+1]
				}
				raw, _ := hex.DecodeString(d)
				didx = binary.LittleEndian.AppendUint64(didx, end)
				didx = append(didx, raw...)
				s.known[d] = true
			}
		}
		s.mu.Unlock()
		if found == nil {
			httpError(w, 404, "no previous backup")
			return
		}
		w.Write(didx) //nolint:errcheck

	case "GET /previous_backup_time":
		fmt.Fprint(w, `{"data":null}`)

	case "POST /finish":
		s.mu.Lock()
		s.finished++
		s.mu.Unlock()

	default:
		httpError(w, 404, "fake pbs: no endpoint %s %s", r.Method, r.URL.Path)
	}
}
