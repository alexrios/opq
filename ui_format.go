package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

// uiIsTTY reports whether f refers to an interactive terminal.
func uiIsTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// uiColorEnabled reports whether subtle ANSI styling should be emitted.
// Respects NO_COLOR (https://no-color.org/) and TERM=dumb, and never emits
// escape sequences to non-TTY streams.
func uiColorEnabled(isTTY bool) bool {
	if !isTTY {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return true
}

// uiStyler wraps text with subtle ANSI SGR sequences when color is enabled.
type uiStyler struct {
	color bool
}

func newUIStyler(isTTY bool) uiStyler {
	return uiStyler{color: uiColorEnabled(isTTY)}
}

func (u uiStyler) wrap(code, s string) string {
	if !u.color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (u uiStyler) dim(s string) string     { return u.wrap("2", s) }
func (u uiStyler) bold(s string) string    { return u.wrap("1", s) }
func (u uiStyler) red(s string) string     { return u.wrap("31", s) }
func (u uiStyler) boldRed(s string) string { return u.wrap("1;31", s) }
func (u uiStyler) yellow(s string) string  { return u.wrap("33", s) }
func (u uiStyler) green(s string) string   { return u.wrap("32", s) }
func (u uiStyler) cyan(s string) string    { return u.wrap("36", s) }

// uiCell is a single table cell whose optional style function is applied
// after text/tabwriter calculates column widths so ANSI escape codes never
// skew column alignment.
type uiCell struct {
	text  string
	style func(string) string
}

// uiCellMarker wraps every cell during tabwriter layout so post-pass styling
// can locate exact cell boundaries without changing relative column widths.
const uiCellMarker = '\x1f'

// uiSanitizeCell strips ASCII control bytes (including ESC, CR, LF, TAB, and
// uiCellMarker) from display text so table columns stay aligned and untrusted
// log or metadata fields cannot inject terminal escape sequences.
func uiSanitizeCell(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			var b strings.Builder
			b.Grow(len(s))
			for j := 0; j < len(s); j++ {
				if s[j] < 0x20 || s[j] == 0x7f {
					b.WriteByte(' ')
				} else {
					b.WriteByte(s[j])
				}
			}
			return b.String()
		}
	}
	return s
}

// uiRenderTable writes an aligned table using text/tabwriter, applying each
// cell's optional ANSI styler after column alignment so escape codes do not
// disturb spacing. headers may be nil for headerless aligned listings.
func uiRenderTable(w io.Writer, headers []string, headerStyle func(string) string, rows [][]uiCell) error {
	allRows := make([][]uiCell, 0, len(rows)+1)
	if len(headers) > 0 {
		hdr := make([]uiCell, len(headers))
		for i, h := range headers {
			hdr[i] = uiCell{text: h, style: headerStyle}
		}
		allRows = append(allRows, hdr)
	}
	allRows = append(allRows, rows...)
	if len(allRows) == 0 {
		return nil
	}

	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	for _, row := range allRows {
		for i, cell := range row {
			if i > 0 {
				tw.Write([]byte{'\t'})
			}
			tw.Write([]byte{uiCellMarker})
			io.WriteString(tw, uiSanitizeCell(cell.text))
			tw.Write([]byte{uiCellMarker})
		}
		tw.Write([]byte{'\n'})
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	rawLines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	for rIdx, line := range rawLines {
		if rIdx >= len(allRows) {
			break
		}
		row := allRows[rIdx]
		var out strings.Builder
		out.Grow(len(line) + 16)
		col := 0
		for i := 0; i < len(line); {
			if line[i] == uiCellMarker {
				end := strings.IndexByte(line[i+1:], uiCellMarker)
				if end < 0 {
					out.WriteString(line[i+1:])
					break
				}
				cellText := line[i+1 : i+1+end]
				if col < len(row) && row[col].style != nil && cellText != "" {
					out.WriteString(row[col].style(cellText))
				} else {
					out.WriteString(cellText)
				}
				col++
				i = i + 1 + end + 1
				continue
			}
			out.WriteByte(line[i])
			i++
		}
		rendered := strings.TrimRight(out.String(), " ")
		if _, err := io.WriteString(w, rendered+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// uiFormatUTC formats a timestamp concisely in UTC for human displays.
func uiFormatUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// uiFormatDuration renders a positive duration in compact human units
// (e.g. "45s", "12m", "4h", "4h30m", "7d", "2d6h").
func uiFormatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	if d == 0 {
		return "0s"
	}
	if d < time.Second {
		return "<1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	if d < time.Hour {
		mins := int((d + 30*time.Second) / time.Minute)
		if mins >= 60 {
			return "1h"
		}
		return fmt.Sprintf("%dm", mins)
	}
	if d < 24*time.Hour {
		totalMins := int((d + 30*time.Second) / time.Minute)
		if totalMins >= 24*60 {
			return "1d"
		}
		h := totalMins / 60
		m := totalMins % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	totalHours := int((d + 30*time.Minute) / time.Hour)
	days := totalHours / 24
	remHours := totalHours % 24
	if days >= 14 || remHours == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, remHours)
}

// uiFormatExpiry renders an expiry timestamp with relative duration and UTC
// timestamp, e.g. "expires in 4h (2026-06-14 12:00 UTC)" or
// "expired 2h ago (2026-06-14 06:00 UTC)".
func uiFormatExpiry(expiresAt, now time.Time) string {
	utc := uiFormatUTC(expiresAt)
	if !now.Before(expiresAt) {
		ago := now.Sub(expiresAt)
		if ago < time.Second {
			return fmt.Sprintf("expired just now (%s)", utc)
		}
		return fmt.Sprintf("expired %s ago (%s)", uiFormatDuration(ago), utc)
	}
	return fmt.Sprintf("expires in %s (%s)", uiFormatDuration(expiresAt.Sub(now)), utc)
}
