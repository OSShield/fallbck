package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/osshield/fallbck/pkg/agent/credstore"
	"github.com/osshield/fallbck/pkg/vcs"
)

// vcsCommand implements `fallbck-agent vcs ...`: credential profiles that keep VCS
// tokens on the agent, so the server never holds them
func vcsCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, vcsUsage)
		return errors.New("missing subcommand")
	}
	switch args[0] {
	case "profile":
		return vcsProfileCommand(args[1:])
	default:
		return fmt.Errorf("unknown vcs command %q\n%s", args[0], vcsUsage)
	}
}

const vcsUsage = `Usage:
  fallbck-agent vcs profile create --name <name> --url <connection URL> (--ask-token | --token-file <path>) [--username <u>]
  fallbck-agent vcs profile list
  fallbck-agent vcs profile delete --name <name>
  fallbck-agent vcs profile test --name <name> [--provider gitlab|github] [--ca-file <pem>]   # check the token, record its expiry
Every command takes --config <agent.yaml> (default: the enrolled agent's file). A job uses a
profile by naming it; the agent sends its token only to the profile's URL, which must equal the
job's connection URL. Tokens are encrypted under <data dir>/credentials.key; only names, URLs
and expiry dates are reported to the server. --ask-token reads from the terminal without echo,
or one line from standard input when piped.
`

func vcsProfileCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, vcsUsage)
		return errors.New("missing profile subcommand")
	}
	fs := flag.NewFlagSet("vcs profile "+args[0], flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to agent.yaml")
	name := fs.String("name", "", "Profile name (jobs reference it)")
	url := fs.String("url", "", "The connection URL the token is for (https://gitlab.example.com)")
	username := fs.String("username", "", "Username for basic authentication (default oauth2, which GitLab accepts)")
	tokenFile := fs.String("token-file", "", "File holding the token (read at every run)")
	askToken := fs.Bool("ask-token", false, "Prompt for the token without echo (or read one line from standard input)")
	caFile := fs.String("ca-file", "", "test: CA bundle for an instance with a private CA")
	provider := fs.String("provider", "", "test: gitlab or github (default: github for github.com, else gitlab; GitHub Enterprise Server needs github)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfgPath, err := agentConfigPath(*configPath)
	if err != nil {
		return err
	}
	dataDir, err := dataDirOf(cfgPath)
	if err != nil {
		return err
	}
	store := credstore.Open(dataDir)

	switch args[0] {
	case "create", "update", "set":
		if *name == "" || *url == "" {
			return errors.New("--name and --url are required")
		}
		p := vcs.Profile{URL: *url, Username: *username, TokenFile: *tokenFile}
		if *askToken {
			if p.TokenFile != "" {
				return errors.New("use either --ask-token or --token-file")
			}
			token, err := readPassword("Token for " + *name + ": ")
			if err != nil {
				return err
			}
			p.Token = token
		}
		if err := store.PutVCS(*name, p); err != nil {
			return err
		}
		fmt.Printf("VCS profile %q saved to %s (encrypted). The agent reports it with its next inventory summary.\n", vcs.NormalizeProfileName(*name), store.Path())
		fmt.Println("For GitLab, check the token and record its expiry with: fallbck-agent vcs profile test --name " + vcs.NormalizeProfileName(*name))
		return nil
	case "list", "ls":
		profiles, err := store.LoadVCS()
		if err != nil {
			return err
		}
		if len(profiles) == 0 {
			fmt.Println("No VCS profiles in the encrypted store.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NAME\tURL\tTOKEN\tEXPIRES")
		for _, s := range credstore.VCSSummaries(profiles) {
			source, expires := "stored", "-"
			if s.TokenFile {
				source = "file " + profiles[s.Name].TokenFile
			}
			if s.TokenExpires != nil {
				expires = s.TokenExpires.Format(time.DateOnly)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, s.URL, source, expires)
		}
		return w.Flush()
	case "delete", "remove", "rm":
		if *name == "" {
			return errors.New("--name is required")
		}
		if err := store.DeleteVCS(*name); err != nil {
			return err
		}
		fmt.Printf("VCS profile %q removed.\n", vcs.NormalizeProfileName(*name))
		return nil
	case "test":
		if *name == "" {
			return errors.New("--name is required")
		}
		return testVCSProfile(store, *name, *provider, *caFile)
	default:
		return fmt.Errorf("unknown profile command %q\n%s", args[0], vcsUsage)
	}
}

// testVCSProfile checks a profile's token against GitLab or GitHub from this host and
// records the expiry the provider reports
func testVCSProfile(store *credstore.Store, name, provider, caFile string) error {
	p, err := store.VCSProfile(name)
	if err != nil {
		return err
	}
	token, err := p.ResolveToken()
	if err != nil {
		return err
	}
	guessed := false
	switch provider = strings.ToLower(strings.TrimSpace(provider)); provider {
	case vcs.ProviderGitLab, vcs.ProviderGitHub:
	case "":
		provider, guessed = vcs.ProviderGitLab, !vcs.IsGitHubCom(p.URL)
		if !guessed {
			provider = vcs.ProviderGitHub
		}
	default:
		return fmt.Errorf("--provider must be %s or %s", vcs.ProviderGitLab, vcs.ProviderGitHub)
	}
	creds := vcs.Credentials{Provider: provider, BaseURL: p.URL, Token: token}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return err
		}
		creds.CAPEM = string(data)
	}
	client, err := creds.HTTPClient(30 * time.Second)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inst, err := vcs.TestConnection(ctx, creds, client)
	if inst != nil {
		if provider == vcs.ProviderGitHub {
			fmt.Printf("GitHub, token of %s\n", inst.Username)
		} else {
			fmt.Printf("GitLab %s, token of %s (admin: %v)\n", inst.Version, inst.Username, inst.IsAdmin)
		}
		if len(inst.Scopes) > 0 {
			fmt.Printf("Scopes: %s\n", strings.Join(inst.Scopes, ", "))
		}
		for _, w := range inst.Warnings {
			fmt.Println("Warning:", w)
		}
		if inst.TokenExpires != nil && (p.TokenExpires == nil || !p.TokenExpires.Equal(*inst.TokenExpires)) {
			p.TokenExpires = inst.TokenExpires
			if perr := store.PutVCS(name, *p); perr != nil {
				return fmt.Errorf("recording the token expiry: %w", perr)
			}
			fmt.Printf("Token expires %s (recorded; the server warns 30 days ahead).\n", inst.TokenExpires.Format(time.DateOnly))
		}
	}
	if err != nil {
		if guessed {
			return fmt.Errorf("%w (tested as GitLab; for GitHub Enterprise Server pass --provider github)", err)
		}
		return err
	}
	fmt.Println("The token works.")
	return nil
}
