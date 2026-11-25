package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

const defaultAuditTailN = 20

type AuditCmd struct {
	Tail   int    `name:"tail" short:"n" default:"20" help:"Number of trailing entries to show (ignored when --all is set; non-positive falls back to 20)."`
	All    bool   `name:"all" help:"Show all available entries across the active and rotated audit log."`
	JSON   bool   `name:"json" help:"Emit raw JSONL lines even when stdout is a TTY."`
	Caller string `name:"caller" enum:",cli,mcp" default:"" help:"Filter entries by caller (cli or mcp)."`
	Action string `name:"action" help:"Filter entries by action (e.g. get, set, exec_inject, mcp_run, denied)."`
	Secret string `name:"secret" help:"Filter entries referencing this secret name."`
}

func validateAuditCallerFilter(caller string) error {
	switch caller {
	case "", "cli", "mcp":
		return nil
	default:
		return fmt.Errorf("invalid --caller %q (want cli or mcp)", caller)
	}
}

func auditEventMatches(ev AuditEvent, caller, action, secret string) bool {
	if caller != "" {
		if ev.Caller != caller && !strings.HasPrefix(ev.Caller, caller+":") {
			return false
		}
	}
	if action != "" && ev.Action != action {
		return false
	}
	if secret != "" {
		if ev.SecretName != secret && !slices.Contains(ev.SecretNames, secret) {
			return false
		}
	}
	return true
}

func (c *AuditCmd) Run() error {
	return c.runWith(tailAudit, os.Stdout, os.Stderr, uiIsTTY(os.Stdout))
}

func (c *AuditCmd) runWith(readLines func(n int) ([]string, error), stdout, stderr io.Writer, stdoutIsTTY bool) error {
	if err := validateAuditCallerFilter(c.Caller); err != nil {
		return err
	}

	limit := c.Tail
	if !c.All && limit <= 0 {
		limit = defaultAuditTailN
	}

	hasFilter := c.Caller != "" || c.Action != "" || c.Secret != ""

	// CLI never uses clampAuditTailN (the 200-entry cap is an MCP AI limit).
	// When --all or any filter is set, read all available entries across the
	// active and rotated logs so filters apply BEFORE taking the trailing N.
	fetchN := limit
	if c.All || hasFilter {
		fetchN = 0
	}
	lines, err := readLines(fetchN)
	if err != nil {
		return err
	}

	type matchedLine struct {
		raw    string
		ev     AuditEvent
		parsed bool
	}

	matched := make([]matchedLine, 0, len(lines))
	for _, l := range lines {
		var ev AuditEvent
		parsed := json.Unmarshal([]byte(l), &ev) == nil
		if hasFilter {
			if !parsed || !auditEventMatches(ev, c.Caller, c.Action, c.Secret) {
				continue
			}
		}
		matched = append(matched, matchedLine{raw: l, ev: ev, parsed: parsed})
	}

	if !c.All && limit > 0 && len(matched) > limit {
		matched = matched[len(matched)-limit:]
	}

	// Non-TTY or --json: emit raw JSONL lines (backwards compatible).
	if !stdoutIsTTY || c.JSON {
		for _, m := range matched {
			fmt.Fprintln(stdout, m.raw)
		}
		return nil
	}

	// TTY table mode.
	if len(matched) == 0 {
		if hasFilter {
			fmt.Fprintln(stderr, "no matching audit entries found")
		} else {
			fmt.Fprintln(stderr, "no audit entries recorded yet")
		}
		return nil
	}

	styler := newUIStyler(true)
	rows := make([][]uiCell, 0, len(matched))
	for _, m := range matched {
		if !m.parsed {
			rows = append(rows, []uiCell{
				{text: "-"},
				{text: "-"},
				{text: "malformed", style: styler.red},
				{text: "-"},
				{text: m.raw},
			})
			continue
		}
		ts := "-"
		if !m.ev.Timestamp.IsZero() {
			ts = m.ev.Timestamp.UTC().Format("2006-01-02 15:04:05Z")
		}
		caller := m.ev.Caller
		if caller == "" {
			caller = "-"
		}
		action := m.ev.Action
		if action == "" {
			action = "-"
		}
		secret := "-"
		switch {
		case m.ev.SecretName != "":
			secret = m.ev.SecretName
		case len(m.ev.SecretNames) > 0:
			secret = strings.Join(m.ev.SecretNames, ",")
		}
		rows = append(rows, []uiCell{
			{text: ts, style: styler.dim},
			{text: caller},
			{text: action, style: auditActionStyle(action, styler)},
			{text: secret},
			{text: m.ev.Message},
		})
	}
	return uiRenderTable(stdout, []string{"TIME", "CALLER", "ACTION", "SECRET", "DETAIL"}, styler.dim, rows)
}

func auditActionStyle(action string, styler uiStyler) func(string) string {
	switch action {
	case ActionDenied:
		return styler.red
	case ActionRedactionDisabled:
		return styler.boldRed
	case ActionNetworkAllowed:
		return styler.yellow
	default:
		return nil
	}
}
