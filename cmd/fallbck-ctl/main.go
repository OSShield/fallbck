package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
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
  agents    list, get, delete agents
  targets   create, list, delete PBS backup targets
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
		fmt.Println("Enroll agent command (filesystem agent / database agent):")
		fmt.Printf("  fallbck-agent enroll --server %s --token %s\n", serverURL, tokenResp.RawToken)
		fmt.Printf("  fallbck-db-agent enroll --server %s --token %s\n", serverURL, tokenResp.RawToken)

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
	}
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
	}
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
	fmt.Fprintln(w, "ID\tJOB\tSTATUS\tSCANNED\tUPLOADED\tDEDUP\tSTARTED")
	for _, r := range runs {
		started := r.CreatedAt.Format("2006-01-02 15:04")
		if r.StartTime != nil {
			started = r.StartTime.Format("15:04:05")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d MB\t%d MB\t%.2fx\t%s\n",
			r.ID.String()[:8], r.JobName, r.Status,
			r.BytesScanned/(1024*1024), r.BytesUploaded/(1024*1024),
			r.DedupRatio, started,
		)
	}
	w.Flush()
}
