package m365

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	spec "github.com/osshield/fallbck/pkg/m365"
)

// Principal is a user of the tenant as the job sees it
type Principal struct {
	ID          string `json:"id"`
	UPN         string `json:"userPrincipalName"`
	DisplayName string `json:"displayName"`
	Mail        string `json:"mail"`
	UserType    string `json:"userType"`
	Enabled     bool   `json:"accountEnabled"`
	Licenses    []struct {
		SKU string `json:"skuId"`
	} `json:"assignedLicenses"`
}

// Licensed reports whether the account holds a licence
func (p Principal) Licensed() bool { return len(p.Licenses) > 0 }

// Site is a SharePoint site
type Site struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	WebURL      string `json:"webUrl"`
}

// Team is a Microsoft 365 group that is a team
type Team struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// SelectUsers lists the tenant's users and applies the job's selection: members of
// the named groups (or everyone), licensed accounts plus shared mailboxes (accounts
// with a mail address but no licence) unless Unlicensed asks for every account,
// never guests, then the UPN include/exclude globs
func SelectUsers(ctx context.Context, c *Client, sel spec.UserSelection) ([]Principal, []string, error) {
	var warnings []string
	all, err := List[Principal](ctx, c, "users?$select=id,userPrincipalName,displayName,mail,userType,accountEnabled,assignedLicenses&$top="+fmt.Sprint(pageSize))
	if err != nil {
		return nil, nil, fmt.Errorf("listing users: %w", err)
	}
	var members map[string]bool
	if len(sel.Groups) > 0 {
		members = map[string]bool{}
		for _, g := range sel.Groups {
			ids, err := groupMembers(ctx, c, g)
			if err != nil {
				return nil, nil, err
			}
			if len(ids) == 0 {
				warnings = append(warnings, fmt.Sprintf("group %q has no user members", g))
			}
			for _, id := range ids {
				members[id] = true
			}
		}
	}
	var out []Principal
	for _, p := range all {
		if strings.EqualFold(p.UserType, "Guest") || p.UPN == "" {
			continue
		}
		if members != nil && !members[p.ID] {
			continue
		}
		if !sel.Unlicensed && !p.Licensed() && (!sel.EffShared() || p.Mail == "") {
			continue
		}
		if !spec.Selected(p.UPN, sel.Include, sel.Exclude) {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].UPN) < strings.ToLower(out[j].UPN) })
	return out, warnings, nil
}

// groupMembers resolves a group by object id or display name and lists the ids of its
// transitive user members
func groupMembers(ctx context.Context, c *Client, group string) ([]string, error) {
	id := group
	if !looksLikeGUID(group) {
		groups, err := List[Team](ctx, c, "groups?$select=id,displayName&$filter=displayName eq "+odataQuote(group))
		if err != nil {
			return nil, fmt.Errorf("resolving group %q: %w", group, err)
		}
		if len(groups) == 0 {
			return nil, fmt.Errorf("group %q not found", group)
		}
		id = groups[0].ID
	}
	users, err := List[Principal](ctx, c, "groups/"+id+"/transitiveMembers/microsoft.graph.user?$select=id&$top="+fmt.Sprint(pageSize))
	if err != nil {
		return nil, fmt.Errorf("listing members of group %q: %w", group, err)
	}
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	return ids, nil
}

func looksLikeGUID(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}

// SelectSites lists every SharePoint site and keeps those the selection names,
// minus the sites that belong to teams (they are archived with their team)
func SelectSites(ctx context.Context, c *Client, sel spec.Selection, teamSites map[string]bool) ([]Site, error) {
	all, err := List[Site](ctx, c, "sites?search=*&$select=id,name,displayName,webUrl")
	if err != nil {
		return nil, fmt.Errorf("listing sites: %w", err)
	}
	var out []Site
	for _, s := range all {
		if teamSites[s.ID] || s.WebURL == "" {
			continue
		}
		if !spec.Selected(siteKey(s.WebURL), sel.Include, sel.Exclude) {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WebURL < out[j].WebURL })
	return out, nil
}

// siteKey is the host + path of a site URL (what globs match against and what names
// the group): contoso.sharepoint.com/sites/HR
func siteKey(webURL string) string {
	u, err := url.Parse(webURL)
	if err != nil {
		return webURL
	}
	return u.Host + strings.TrimRight(u.Path, "/")
}

// SelectTeams lists the groups that are teams and keeps those the selection names
func SelectTeams(ctx context.Context, c *Client, sel spec.Selection) ([]Team, error) {
	all, err := List[Team](ctx, c, "groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName&$top="+fmt.Sprint(pageSize))
	if err != nil {
		return nil, fmt.Errorf("listing teams: %w", err)
	}
	var out []Team
	for _, t := range all {
		if spec.Selected(t.DisplayName, sel.Include, sel.Exclude) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].DisplayName) < strings.ToLower(out[j].DisplayName) })
	return out, nil
}

// teamSiteID returns the SharePoint site of a team (its group)
func teamSiteID(ctx context.Context, c *Client, groupID string) (string, error) {
	var site Site
	if err := c.Get(ctx, "groups/"+groupID+"/sites/root?$select=id,webUrl", &site, nil); err != nil {
		return "", err
	}
	return site.ID, nil
}
