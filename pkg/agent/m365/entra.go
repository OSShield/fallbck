package m365

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// directoryCollections are the Entra ID collections archived as one JSON file each
var directoryCollections = []struct{ name, path string }{
	{"organization", "organization"},
	{"users", "users?$select=id,userPrincipalName,displayName,mail,userType,accountEnabled,assignedLicenses,department,jobTitle,createdDateTime&$top=999"},
	{"groups", "groups?$select=id,displayName,description,mail,groupTypes,securityEnabled,mailEnabled,visibility,resourceProvisioningOptions&$top=999"},
	{"applications", "applications?$top=999"},
	{"service-principals", "servicePrincipals?$top=999"},
	{"directory-roles", "directoryRoles"},
	{"conditional-access", "identity/conditionalAccess/policies"},
	{"named-locations", "identity/conditionalAccess/namedLocations"},
	{"licenses", "subscribedSkus"},
	{"administrative-units", "directory/administrativeUnits"},
	{"domains", "domains"},
}

// collectDirectory dumps the directory collections plus the members of every group
// and directory role. A collection the app may not read is skipped with a warning
// (the permission is named), the rest is still archived.
func collectDirectory(ctx context.Context, c *Client, now time.Time) ([]Entry, []string, error) {
	var entries []Entry
	var warnings []string
	for _, col := range directoryCollections {
		var items []json.RawMessage
		_, err := c.Each(ctx, col.path, nil, func(raw json.RawMessage) error {
			items = append(items, raw)
			return nil
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, err
			}
			warnings = append(warnings, fmt.Sprintf("directory: %s not archived: %v", col.name, err))
			continue
		}
		data, _ := json.MarshalIndent(items, "", "  ")
		entries = append(entries, memEntry(col.name+".json", data, now))
		if col.name == "groups" || col.name == "directory-roles" {
			sub := "groups"
			if col.name == "directory-roles" {
				sub = "roles"
			}
			for _, raw := range items {
				var obj struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(raw, &obj) != nil || obj.ID == "" {
					continue
				}
				var members []json.RawMessage
				_, err := c.Each(ctx, fmt.Sprintf("%s/%s/members?$select=id,displayName,userPrincipalName,mail&$top=999", apiCollection(col.name), obj.ID), nil, func(m json.RawMessage) error {
					members = append(members, m)
					return nil
				})
				if err != nil {
					if ctx.Err() != nil {
						return nil, nil, err
					}
					warnings = append(warnings, fmt.Sprintf("directory: members of %s %s not archived: %v", sub, obj.ID, err))
					continue
				}
				data, _ := json.MarshalIndent(map[string]any{"object": raw, "members": members}, "", "  ")
				entries = append(entries, memEntry(sub+"/"+obj.ID+".json", data, now))
			}
		}
	}
	return entries, warnings, nil
}

func apiCollection(name string) string {
	if name == "directory-roles" {
		return "directoryRoles"
	}
	return "groups"
}
