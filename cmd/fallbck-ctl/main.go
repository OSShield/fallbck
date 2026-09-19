package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/db"
)

var ControlVersion = "0.1.0"

// apiKey is the admin API key (FALLBCK_API_KEY), created in the Web UI under API Keys
var apiKey = os.Getenv("FALLBCK_API_KEY")

// apiRequest performs an authenticated request against the server API
func apiRequest(method, url string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, fmt.Errorf("unauthorized: set FALLBCK_API_KEY to an API key created in the Web UI (API Keys page)")
	}
	return resp, nil
}

func apiGet(url string) (*http.Response, error) { return apiRequest(http.MethodGet, url, nil) }
func apiPost(url string, body []byte) (*http.Response, error) {
	return apiRequest(http.MethodPost, url, body)
}

func main() {
	serverURL := os.Getenv("FALLBCK_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "token":
		handleTokenCommands(serverURL, os.Args[2:])
	case "agents":
		handleAgentCommands(serverURL, os.Args[2:])
	case "targets":
		handleTargetCommands(serverURL, os.Args[2:])
	case "jobs":
		handleJobCommands(serverURL, os.Args[2:])
	case "runs":
		handleRunCommands(serverURL, os.Args[2:])
	case "version":
		fmt.Printf("fallbck-ctl v%s\n", ControlVersion)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`FallBCK Control CLI (fallbck-ctl)

Usage:
  fallbck-ctl <resource> <action> [options]

Resources:
  token     create, list enrollment tokens
  agents    list agents; merge <db-agent> --into <agent> retires a database agent into the combined agent on the same host
  targets   list PBS backup targets; credentials <target> prints proxmox-backup-client exports
  jobs      create, list, get, run backup jobs
  runs      list backup executions

Environment Variables:
  FALLBCK_SERVER_URL   Server endpoint (default: http://localhost:8080)
  FALLBCK_API_KEY      Admin API key (create one in the Web UI under API Keys)`)
}

func handleTokenCommands(serverURL string, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fallbck-ctl token [create|list]")
		return
	}

	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ExitOnError)
		name := fs.String("name", "Default Token", "Token descriptive name")
		maxUses := fs.Int("max-uses", 1, "Max times token can be used (0 for unlimited)")
		days := fs.Int("days", 1, "Validity in days")
		_ = fs.Parse(args[1:])

		reqBody := api.CreateTokenRequest{
			Name:      *name,
			MaxUses:   *maxUses,
			ExpiresAt: time.Now().Add(time.Duration(*days) * 24 * time.Hour),
		}
		b, _ := json.Marshal(reqBody)
		resp, err := apiPost(fmt.Sprintf("%s/api/v1/tokens", serverURL), b)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		defer resp.Body.Close()

		var tokenResp api.CreateTokenResponse
		_ = json.NewDecoder(resp.Body).Decode(&tokenResp)

		fmt.Println("✓ Enrollment Token Created:")
		fmt.Printf("  Token:     %s\n", tokenResp.RawToken)
		fmt.Printf("  Name:      %s\n", tokenResp.Name)
		fmt.Printf("  Max Uses:  %d\n", tokenResp.MaxUses)
		fmt.Printf("  Expires:   %s\n\n", tokenResp.ExpiresAt.Format(time.RFC3339))
		fmt.Println("Enroll agent command:")
		fmt.Printf("  fallbck-agent enroll --server %s --token %s\n", serverURL, tokenResp.RawToken)

	case "list":
		resp, err := apiGet(fmt.Sprintf("%s/api/v1/tokens", serverURL))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		defer resp.Body.Close()

		var tokens []*db.EnrollmentToken
		_ = json.NewDecoder(resp.Body).Decode(&tokens)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tUSES\tEXPIRES\tCREATED")
		for _, t := range tokens {
			fmt.Fprintf(w, "%s\t%s\t%d/%d\t%s\t%s\n",
				t.ID.String()[:8], t.Name, t.UsesCount, t.MaxUses,
				t.ExpiresAt.Format("2006-01-02 15:04"),
				t.CreatedAt.Format("2006-01-02 15:04"),
			)
		}
		w.Flush()
	}
}

func handleAgentCommands(serverURL string, args []string) {
	if len(args) < 1 {
		args = []string{"list"}
	}

	switch args[0] {
	case "list":
		resp, err := apiGet(fmt.Sprintf("%s/api/v1/agents", serverURL))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		defer resp.Body.Close()

		var agents []*db.Agent
		_ = json.NewDecoder(resp.Body).Decode(&agents)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tHOSTNAME\tTYPE\tIP\tOS/ARCH\tSTATUS\tLAST SEEN")
		for _, a := range agents {
			lastSeen := "never"
			if a.LastSeenAt != nil {
				lastSeen = a.LastSeenAt.Format("15:04:05")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s/%s\t%s\t%s\n",
				a.ID.String()[:8], a.Hostname, a.AgentType, a.IPAddress, a.OS, a.Arch, a.Status, lastSeen,
			)
		}
		w.Flush()

	case "merge":
		// fallbck-ctl agents merge <agent id, prefix or hostname> --into <agent id, prefix or hostname>
		fs := flag.NewFlagSet("merge", flag.ExitOnError)
		into := fs.String("into", "", "Agent that takes over the jobs and run history (id, id prefix or hostname)")
		if len(args) < 2 {
			fmt.Println("Usage: fallbck-ctl agents merge <agent> --into <agent>")
			os.Exit(2)
		}
		_ = fs.Parse(args[2:])
		if *into == "" {
			fmt.Println("Error: --into is required")
			os.Exit(2)
		}
		from, err := resolveAgent(serverURL, args[1])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		target, err := resolveAgent(serverURL, *into)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		body, _ := json.Marshal(api.MergeAgentRequest{Into: target.ID})
		resp, err := apiPost(fmt.Sprintf("%s/api/v1/agents/%s/merge", serverURL, from.ID), body)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			var e struct {
				Error string `json:"error"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&e)
			fmt.Printf("Error: %s\n", e.Error)
			os.Exit(1)
		}
		var out api.MergeAgentResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		fmt.Printf("Merged %s (%s) into %s (%s): %d jobs and %d runs moved; the old agent is deleted and its token revoked.\n",
			from.Hostname, from.AgentType, target.Hostname, target.AgentType, out.JobsMoved, out.RunsMoved)
		fmt.Println("On the host: stop and remove fallbck-db-agent (systemctl disable --now fallbck-db-agent; apt remove fallbck-db-agent).")

	default:
		fmt.Println("Usage: fallbck-ctl agents [list|merge <agent> --into <agent>]")
		os.Exit(2)
	}
}

// resolveAgent finds an agent by full id, unique id prefix or unique hostname
func resolveAgent(serverURL, ref string) (*db.Agent, error) {
	resp, err := apiGet(fmt.Sprintf("%s/api/v1/agents", serverURL))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var agents []*db.Agent
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}
	var matches []*db.Agent
	for _, a := range agents {
		id := a.ID.String()
		if id == ref || strings.HasPrefix(id, ref) || a.Hostname == ref {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, fmt.Errorf("no agent matches %q (use the id, an id prefix or the hostname)", ref)
	}
	var names []string
	for _, a := range matches {
		names = append(names, fmt.Sprintf("%s (%s, %s)", a.ID.String()[:8], a.Hostname, a.AgentType))
	}
	return nil, fmt.Errorf("%q is ambiguous: %s", ref, strings.Join(names, ", "))
}

func handleTargetCommands(serverURL string, args []string) {
	if len(args) < 1 {
		args = []string{"list"}
	}

	switch args[0] {
	case "list":
		resp, err := apiGet(fmt.Sprintf("%s/api/v1/targets", serverURL))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		defer resp.Body.Close()

		var targets []*db.BackupTarget
		_ = json.NewDecoder(resp.Body).Decode(&targets)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tTYPE\tENDPOINT\tDATASTORE\tNAMESPACE")
		for _, t := range targets {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				t.ID.String()[:8], t.Name, t.TargetType, t.Endpoint, t.Datastore, t.Namespace,
			)
		}
		w.Flush()
	case "credentials":
		// Prints the PBS connection details of a target as proxmox-backup-client
		// environment exports, for restores done with PBS's own tools (e.g. the
		// Proxmox VE host restore runbook)
		if len(args) < 2 {
			fmt.Println("usage: fallbck-ctl targets credentials <target id, id prefix or name>")
			os.Exit(2)
		}
		target, err := resolveTarget(serverURL, args[1])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		resp, err := apiGet(fmt.Sprintf("%s/api/v1/targets/%s/credentials", serverURL, target.ID))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: %s: %s\n", resp.Status, body)
			os.Exit(1)
		}
		var creds api.TargetCredentials
		if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("# PBS target %q (%s); paste into the shell running proxmox-backup-client\n", target.Name, creds.Endpoint)
		fmt.Printf("export PBS_REPOSITORY=%s\n", shellQuote(creds.Repository))
		fmt.Printf("export PBS_PASSWORD=%s\n", shellQuote(creds.Secret))
		if creds.Fingerprint != "" {
			fmt.Printf("export PBS_FINGERPRINT=%s\n", shellQuote(creds.Fingerprint))
		}
		if creds.Namespace != "" {
			fmt.Printf("# namespace: add --ns %s to proxmox-backup-client commands\n", creds.Namespace)
		}
	default:
		fmt.Println("usage: fallbck-ctl targets [list|credentials <target>]")
		os.Exit(2)
	}
}

// resolveTarget finds a target by full id, id prefix or exact name
func resolveTarget(serverURL, ref string) (*db.BackupTarget, error) {
	resp, err := apiGet(fmt.Sprintf("%s/api/v1/targets", serverURL))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var targets []*db.BackupTarget
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return nil, err
	}
	var matches []*db.BackupTarget
	for _, t := range targets {
		if t.ID.String() == ref || t.Name == ref || strings.HasPrefix(t.ID.String(), ref) {
			matches = append(matches, t)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no target matches %q", ref)
	case 1:
		return matches[0], nil
	}
	return nil, fmt.Errorf("%q matches %d targets; use the full id", ref, len(matches))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func handleJobCommands(serverURL string, args []string) {
	if len(args) < 1 {
		args = []string{"list"}
	}

	switch args[0] {
	case "list":
		resp, err := apiGet(fmt.Sprintf("%s/api/v1/jobs", serverURL))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		defer resp.Body.Close()

		var jobs []*db.BackupJob
		_ = json.NewDecoder(resp.Body).Decode(&jobs)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tTYPE\tAGENT\tTARGET\tSOURCE\tSCHEDULE\tENABLED")
		for _, j := range jobs {
			sched := j.ScheduleCron
			if sched == "" {
				sched = "manual"
			}
			jobType := j.JobType
			if jobType == "" {
				jobType = "filesystem"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%t\n",
				j.ID.String()[:8], j.Name, jobType, j.AgentName, j.TargetName, j.Summary(), sched, j.Enabled,
			)
		}
		w.Flush()

	case "run":
		if len(args) < 2 {
			fmt.Println("Usage: fallbck-ctl jobs run <job-id>")
			return
		}
		jobID := args[1]
		resp, err := apiPost(fmt.Sprintf("%s/api/v1/jobs/%s/run", serverURL, jobID), nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Job trigger response: %s\n", string(body))
	}
}

func handleRunCommands(serverURL string, args []string) {
	resp, err := apiGet(fmt.Sprintf("%s/api/v1/runs", serverURL))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var runs []*db.BackupRun
	_ = json.NewDecoder(resp.Body).Decode(&runs)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tJOB\tSTATUS\tSCANNED\tUPLOADED\tDEDUP\tSTARTED\tDURATION")
	for _, r := range runs {
		started := r.CreatedAt.Format("2006-01-02 15:04")
		if r.StartTime != nil {
			started = r.StartTime.Format("15:04:05")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d MB\t%d MB\t%.2fx\t%s\t%s\n",
			r.ID.String()[:8], r.JobName, r.Status,
			r.BytesScanned/(1024*1024), r.BytesUploaded/(1024*1024),
			r.DedupRatio, started, r.DurationString(),
		)
	}
	w.Flush()
}
