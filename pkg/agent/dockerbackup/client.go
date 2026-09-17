// Package dockerbackup runs Docker host backups from the filesystem agent: it
// collects container, network, volume and image definitions plus compose files into
// a spool directory, archives them together with every named volume, and generates a
// restore runbook. The daemon is reached through its unix socket with the Engine API
// (no docker client library, no docker CLI needed).
package dockerbackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	dockerspec "github.com/osshield/fallbck/pkg/dockerbackup"
)

// MinAPIVersion is the oldest Engine API the agent talks to (Docker 20.10)
const MinAPIVersion = "1.41"

// Client is a minimal Engine API client over a unix socket
type Client struct {
	http    *http.Client
	socket  string
	version string // negotiated API version, e.g. 1.43
}

// NewClient prepares a client for the socket; Negotiate must run before other calls
func NewClient(socket string) *Client {
	if socket == "" {
		socket = dockerspec.SocketPath()
	}
	return &Client{
		http:   &http.Client{Transport: dockerspec.SocketTransport(socket)},
		socket: socket,
	}
}

// Socket returns the socket path
func (c *Client) Socket() string { return c.socket }

// APIVersion returns the negotiated version
func (c *Client) APIVersion() string { return c.version }

// Negotiate reads the daemon's API version and pins requests to it
func (c *Client) Negotiate(ctx context.Context) (*Version, error) {
	c.version = ""
	var v Version
	if err := c.get(ctx, "/version", nil, &v); err != nil {
		return nil, err
	}
	if v.APIVersion == "" || versionLess(v.APIVersion, MinAPIVersion) {
		return nil, fmt.Errorf("docker API version %q is older than the supported minimum %s", v.APIVersion, MinAPIVersion)
	}
	c.version = v.APIVersion
	return &v, nil
}

// versionLess compares dotted API versions ("1.41" < "1.43")
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var na, nb int
		if i < len(pa) {
			na, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			nb, _ = strconv.Atoi(pb[i])
		}
		if na != nb {
			return na < nb
		}
	}
	return false
}

func (c *Client) url(path string, query url.Values) string {
	u := "http://docker"
	if c.version != "" {
		u += "/v" + c.version
	}
	u += path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}

// do performs a request and maps non-2xx answers to StatusError
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path, query), rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		se := &dockerspec.StatusError{Status: resp.StatusCode}
		var em struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(msg, &em) == nil && em.Message != "" {
			se.Message = em.Message
		} else if t := strings.TrimSpace(string(msg)); t != "" {
			se.Message = t
		}
		return nil, fmt.Errorf("docker %s %s: %w", method, path, se)
	}
	return resp, nil
}

// get decodes a JSON answer into out (raw receives the bytes when non-nil)
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	_, err := c.getRaw(ctx, path, query, out)
	return err
}

func (c *Client) getRaw(ctx context.Context, path string, query url.Values, out any) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("docker GET %s: reading answer: %w", path, err)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return nil, fmt.Errorf("docker GET %s: decoding answer: %w", path, err)
		}
	}
	return data, nil
}

// post sends a JSON body (nil for none) and decodes the answer into out when non-nil
func (c *Client) post(ctx context.Context, path string, query url.Values, body, out any) error {
	resp, err := c.do(ctx, http.MethodPost, path, query, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// stream returns the body of a GET (tar streams); the caller closes it
func (c *Client) stream(ctx context.Context, path string, query url.Values) (io.ReadCloser, error) {
	resp, err := c.do(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// IsNotFound reports a 404 from the daemon
func IsNotFound(err error) bool {
	var se *dockerspec.StatusError
	return errors.As(err, &se) && se.Status == http.StatusNotFound
}

// ---- Types (the subset of the Engine API the agent uses) --------------------

// Version is GET /version
type Version struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	OS            string `json:"Os"`
	Arch          string `json:"Arch"`
	KernelVersion string `json:"KernelVersion"`
}

// Info is GET /info
type Info struct {
	ID                string   `json:"ID"`
	Name              string   `json:"Name"`
	ServerVersion     string   `json:"ServerVersion"`
	DockerRootDir     string   `json:"DockerRootDir"`
	Driver            string   `json:"Driver"`
	OperatingSystem   string   `json:"OperatingSystem"`
	OSType            string   `json:"OSType"`
	Architecture      string   `json:"Architecture"`
	KernelVersion     string   `json:"KernelVersion"`
	Containers        int      `json:"Containers"`
	ContainersRunning int      `json:"ContainersRunning"`
	Images            int      `json:"Images"`
	SecurityOptions   []string `json:"SecurityOptions"`
	Swarm             struct {
		LocalNodeState   string `json:"LocalNodeState"`
		ControlAvailable bool   `json:"ControlAvailable"`
	} `json:"Swarm"`
}

// Rootless reports whether the daemon runs rootless
func (i *Info) Rootless() bool {
	for _, o := range i.SecurityOptions {
		if strings.Contains(o, "rootless") {
			return true
		}
	}
	return false
}

// ContainerSummary is one element of GET /containers/json
type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
}

// Name returns the primary name without the leading slash
func (c *ContainerSummary) Name() string {
	if len(c.Names) == 0 {
		return c.ID[:min(12, len(c.ID))]
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// ContainerInspect is GET /containers/{id}/json (the fields the manifest and the
// restore script use; the raw document is archived as well)
type ContainerInspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	Image   string `json:"Image"`
	State   struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
		Paused  bool   `json:"Paused"`
	} `json:"State"`
	Config struct {
		Hostname     string              `json:"Hostname"`
		User         string              `json:"User"`
		Env          []string            `json:"Env"`
		Cmd          []string            `json:"Cmd"`
		Entrypoint   []string            `json:"Entrypoint"`
		Image        string              `json:"Image"`
		WorkingDir   string              `json:"WorkingDir"`
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	HostConfig struct {
		Binds         []string `json:"Binds"`
		NetworkMode   string   `json:"NetworkMode"`
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
		Privileged bool     `json:"Privileged"`
		CapAdd     []string `json:"CapAdd"`
		CapDrop    []string `json:"CapDrop"`
		ExtraHosts []string `json:"ExtraHosts"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		Driver      string `json:"Driver"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string   `json:"IPAddress"`
			Aliases   []string `json:"Aliases"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// CleanName returns the container name without the leading slash
func (c *ContainerInspect) CleanName() string { return strings.TrimPrefix(c.Name, "/") }

// NetworkInspect is GET /networks/{id} (and the list elements)
type NetworkInspect struct {
	Name       string `json:"Name"`
	ID         string `json:"Id"`
	Driver     string `json:"Driver"`
	Scope      string `json:"Scope"`
	Internal   bool   `json:"Internal"`
	Attachable bool   `json:"Attachable"`
	EnableIPv6 bool   `json:"EnableIPv6"`
	IPAM       struct {
		Driver string `json:"Driver"`
		Config []struct {
			Subnet  string `json:"Subnet"`
			Gateway string `json:"Gateway"`
			IPRange string `json:"IPRange"`
		} `json:"Config"`
	} `json:"IPAM"`
	Options    map[string]string `json:"Options"`
	Labels     map[string]string `json:"Labels"`
	Containers map[string]struct {
		Name string `json:"Name"`
	} `json:"Containers"`
}

// VolumeInspect is GET /volumes/{name} (and the list elements)
type VolumeInspect struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	Scope      string            `json:"Scope"`
	CreatedAt  string            `json:"CreatedAt"`
	Labels     map[string]string `json:"Labels"`
	Options    map[string]string `json:"Options"`
}

// ImageSummary is one element of GET /images/json
type ImageSummary struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	Size        int64    `json:"Size"`
}

// ---- Calls ------------------------------------------------------------------

// Info is GET /info
func (c *Client) Info(ctx context.Context) (*Info, []byte, error) {
	var i Info
	raw, err := c.getRaw(ctx, "/info", nil, &i)
	return &i, raw, err
}

// ListContainers lists every container (all=1) or only running ones
func (c *Client) ListContainers(ctx context.Context, all bool) ([]ContainerSummary, error) {
	q := url.Values{}
	if all {
		q.Set("all", "1")
	}
	var out []ContainerSummary
	return out, c.get(ctx, "/containers/json", q, &out)
}

// InspectContainer returns the parsed and the raw inspect document
func (c *Client) InspectContainer(ctx context.Context, id string) (*ContainerInspect, []byte, error) {
	var ci ContainerInspect
	raw, err := c.getRaw(ctx, "/containers/"+url.PathEscape(id)+"/json", nil, &ci)
	return &ci, raw, err
}

// ListNetworks lists every network
func (c *Client) ListNetworks(ctx context.Context) ([]NetworkInspect, error) {
	var out []NetworkInspect
	return out, c.get(ctx, "/networks", nil, &out)
}

// InspectNetwork returns the parsed and the raw network document
func (c *Client) InspectNetwork(ctx context.Context, id string) (*NetworkInspect, []byte, error) {
	var n NetworkInspect
	raw, err := c.getRaw(ctx, "/networks/"+url.PathEscape(id), nil, &n)
	return &n, raw, err
}

// ListVolumes lists every volume
func (c *Client) ListVolumes(ctx context.Context) ([]VolumeInspect, error) {
	var out struct {
		Volumes  []VolumeInspect `json:"Volumes"`
		Warnings []string        `json:"Warnings"`
	}
	return out.Volumes, c.get(ctx, "/volumes", nil, &out)
}

// InspectVolume returns the parsed and the raw volume document
func (c *Client) InspectVolume(ctx context.Context, name string) (*VolumeInspect, []byte, error) {
	var v VolumeInspect
	raw, err := c.getRaw(ctx, "/volumes/"+url.PathEscape(name), nil, &v)
	return &v, raw, err
}

// ListImages lists every image (including untagged ones)
func (c *Client) ListImages(ctx context.Context) ([]ImageSummary, []byte, error) {
	var out []ImageSummary
	raw, err := c.getRaw(ctx, "/images/json", nil, &out)
	return out, raw, err
}

// SaveImages streams `docker save` of the named images
func (c *Client) SaveImages(ctx context.Context, names []string) (io.ReadCloser, error) {
	q := url.Values{}
	for _, n := range names {
		q.Add("names", n)
	}
	return c.stream(ctx, "/images/get", q)
}

// Pause / Unpause freeze and thaw a running container
func (c *Client) Pause(ctx context.Context, id string) error {
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/pause", nil, nil, nil)
}
func (c *Client) Unpause(ctx context.Context, id string) error {
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/unpause", nil, nil, nil)
}

// EnsureImage pulls the image when it is missing locally
func (c *Client) EnsureImage(ctx context.Context, ref string) error {
	err := c.get(ctx, "/images/"+url.PathEscape(ref)+"/json", nil, nil)
	if err == nil {
		return nil
	}
	if !IsNotFound(err) {
		return err
	}
	q := url.Values{"fromImage": {ref}}
	if i := strings.LastIndex(ref, ":"); i > 0 && !strings.Contains(ref[i:], "/") {
		q.Set("fromImage", ref[:i])
		q.Set("tag", ref[i+1:])
	}
	resp, err := c.do(ctx, http.MethodPost, "/images/create", q, nil)
	if err != nil {
		return fmt.Errorf("pulling %s: %w", ref, err)
	}
	defer resp.Body.Close()
	// The pull streams progress messages; an error is reported inside the stream
	dec := json.NewDecoder(resp.Body)
	for {
		var msg struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("pulling %s: %w", ref, err)
		}
		if msg.Error != "" {
			return fmt.Errorf("pulling %s: %s", ref, msg.Error)
		}
	}
}

// HelperSpec describes a throwaway container used to read volumes or host paths
type HelperSpec struct {
	Name  string
	Image string
	// Binds are host-config binds ("volume:/vol:ro", "/host/dir:/src:ro")
	Binds []string
	// Labels mark the container as ours (sweeps, manifests)
	Labels map[string]string
}

// CreateHelper creates (without starting) a helper container and returns its id.
// A created container is enough for /containers/{id}/archive: the daemon mounts its
// volumes for the copy, so no process runs inside it.
func (c *Client) CreateHelper(ctx context.Context, spec HelperSpec) (string, error) {
	body := map[string]any{
		"Image":  spec.Image,
		"Cmd":    []string{"true"},
		"Labels": spec.Labels,
		"HostConfig": map[string]any{
			"Binds":       spec.Binds,
			"NetworkMode": "none",
			"AutoRemove":  false,
		},
	}
	q := url.Values{}
	if spec.Name != "" {
		q.Set("name", spec.Name)
	}
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := c.post(ctx, "/containers/create", q, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// RemoveContainer force-removes a container (helpers only)
func (c *Client) RemoveContainer(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url("/containers/"+url.PathEscape(id), url.Values{"force": {"1"}, "v": {"0"}}), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return &dockerspec.StatusError{Status: resp.StatusCode}
	}
	return nil
}

// Archive streams a tar of path inside the container (GET /containers/{id}/archive)
func (c *Client) Archive(ctx context.Context, id, path string) (io.ReadCloser, error) {
	return c.stream(ctx, "/containers/"+url.PathEscape(id)+"/archive", url.Values{"path": {path}})
}

// callTimeout bounds one plain API call (lists, inspects, pause)
const callTimeout = 2 * time.Minute

// withTimeout derives a bounded context for a plain call
func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, callTimeout)
}
