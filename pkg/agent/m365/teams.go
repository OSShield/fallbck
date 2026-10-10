package m365

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// teamsStats counts one team
type teamsStats struct {
	Channels, Messages, NewMessages, Hosted int
}

// hostedContentRe finds hosted content references in message bodies
var hostedContentRe = regexp.MustCompile(`https://graph\.microsoft\.com/v1\.0/teams/([^/"']+)/channels/([^/"']+)/messages/([^/"']+)/hostedContents/([^/"']+)/\$value`)

// maxHostedBytes bounds one inline image or file
const maxHostedBytes = 100 << 20

// collectTeam fetches the channel messages changed since the last run (all of them on
// the first run), merges them into the per-month files of the index and produces
// the messages/ and hosted/ entries. Messages live in the index: they are small and
// a month file must be re-emitted byte for byte for chunk reuse.
func collectTeam(ctx context.Context, c *Client, teamID string, idx *TeamsIndex, now time.Time, warn func(string)) ([]Entry, teamsStats, error) {
	var st teamsStats
	if idx.Channels == nil {
		idx.Channels = map[string]*ChannelIndex{}
	}
	if idx.Hosted == nil {
		idx.Hosted = map[string]*HostedEntry{}
	}
	type channel struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Membership  string `json:"membershipType"`
	}
	channels, err := List[channel](ctx, c, "teams/"+teamID+"/channels?$select=id,displayName,membershipType")
	if err != nil {
		return nil, st, fmt.Errorf("channels: %w", err)
	}
	st.Channels = len(channels)
	for _, ch := range channels {
		cur := idx.Channels[ch.ID]
		if cur == nil {
			cur = &ChannelIndex{Months: map[string]map[string]json.RawMessage{}}
			idx.Channels[ch.ID] = cur
		}
		cur.Name = ch.DisplayName
	}

	path := "teams/" + teamID + "/channels/getAllMessages"
	if idx.Since != "" {
		// The export API wants a closed range: both bounds, upper one in the future
		path += "?$filter=lastModifiedDateTime gt " + idx.Since + " and lastModifiedDateTime lt " + now.Add(24*time.Hour).UTC().Format("2006-01-02T15:04:05Z")
	}
	newest := idx.Since
	hosted := map[string][]byte{}
	_, err = c.Each(ctx, path, nil, func(raw json.RawMessage) error {
		var msg struct {
			ID       string `json:"id"`
			Created  string `json:"createdDateTime"`
			Modified string `json:"lastModifiedDateTime"`
			Channel  struct {
				ChannelID string `json:"channelId"`
			} `json:"channelIdentity"`
			Body struct {
				Content string `json:"content"`
			} `json:"body"`
		}
		if err := json.Unmarshal(raw, &msg); err != nil {
			return err
		}
		ch := idx.Channels[msg.Channel.ChannelID]
		if ch == nil {
			ch = &ChannelIndex{Name: msg.Channel.ChannelID, Months: map[string]map[string]json.RawMessage{}}
			idx.Channels[msg.Channel.ChannelID] = ch
		}
		month := "unknown"
		if t, err := time.Parse(time.RFC3339Nano, msg.Created); err == nil {
			month = t.UTC().Format("2006-01")
		}
		if ch.Months[month] == nil {
			ch.Months[month] = map[string]json.RawMessage{}
		}
		ch.Months[month][msg.ID] = raw
		st.NewMessages++
		if msg.Modified > newest {
			newest = msg.Modified
		}
		for _, m := range hostedContentRe.FindAllStringSubmatch(msg.Body.Content, -1) {
			key := "hosted/" + shortID(msg.ID) + "-" + shortID(m[4])
			if _, known := idx.Hosted[key]; known {
				continue
			}
			u := "teams/" + m[1] + "/channels/" + m[2] + "/messages/" + m[3] + "/hostedContents/" + m[4] + "/$value"
			data, err := c.ReadAll(ctx, u, maxHostedBytes)
			if err != nil {
				if ctx.Err() != nil {
					return err
				}
				warn(fmt.Sprintf("hosted content of message %s not fetched: %v", msg.ID, err))
				continue
			}
			hosted[key] = data
			mt := now
			if t, err := time.Parse(time.RFC3339Nano, msg.Modified); err == nil {
				mt = t
			}
			idx.Hosted[key] = &HostedEntry{URL: u, Size: int64(len(data)), Mtime: mt.Unix()}
			st.Hosted++
		}
		return nil
	})
	if err != nil {
		return nil, st, fmt.Errorf("channel messages: %w", err)
	}
	idx.Since = newest

	var entries []Entry
	seenNames := map[string]int{}
	for _, chID := range sortedKeys(idx.Channels) {
		ch := idx.Channels[chID]
		dir := safeComponent(ch.Name)
		if n := seenNames[dir]; n > 0 {
			dir = fmt.Sprintf("%s-%d", dir, n)
		}
		seenNames[safeComponent(ch.Name)]++
		for _, month := range sortedKeys(ch.Months) {
			msgs := ch.Months[month]
			st.Messages += len(msgs)
			ids := sortedKeys(msgs)
			var buf bytes.Buffer
			buf.WriteString("[\n")
			var latest string
			for i, id := range ids {
				if i > 0 {
					buf.WriteString(",\n")
				}
				buf.Write(msgs[id])
				var m struct {
					Modified string `json:"lastModifiedDateTime"`
				}
				if json.Unmarshal(msgs[id], &m) == nil && m.Modified > latest {
					latest = m.Modified
				}
			}
			buf.WriteString("\n]\n")
			// mtime = newest change in the month: the file is reused until the month changes
			mt := now
			if t, err := time.Parse(time.RFC3339Nano, latest); err == nil {
				mt = t
			}
			data := buf.Bytes()
			entries = append(entries, Entry{Path: "messages/" + dir + "/" + month + ".json", Size: int64(len(data)), Mtime: mt, Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			}})
		}
	}
	for _, key := range sortedKeys(idx.Hosted) {
		h := idx.Hosted[key]
		u := h.URL
		data := hosted[key]
		entries = append(entries, Entry{Path: key, Size: h.Size, Mtime: time.Unix(h.Mtime, 0).UTC(), Open: func() (io.ReadCloser, error) {
			if data != nil {
				return io.NopCloser(bytes.NewReader(data)), nil
			}
			body, _, err := c.Download(context.Background(), u)
			return body, err
		}})
	}
	chans, _ := json.MarshalIndent(channels, "", "  ")
	entries = append(entries, memEntry("channels.json", chans, now))
	return entries, st, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// teamJSON fetches the team's own description for team.json
func teamJSON(ctx context.Context, c *Client, teamID string) ([]byte, error) {
	var raw json.RawMessage
	if err := c.Get(ctx, "teams/"+teamID, &raw, nil); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return raw, nil
	}
	return buf.Bytes(), nil
}

var _ = strings.TrimSpace
