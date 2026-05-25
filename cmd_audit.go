package main

import (
	"fmt"
	"os"
)

type AuditCmd struct {
	Tail int `name:"tail" short:"n" default:"20" help:"Number of trailing entries to show. Negative or 0 falls back to default (20)."`
}

func (c *AuditCmd) Run() error {
	lines, err := tailAudit(clampAuditTailN(c.Tail))
	if err != nil {
		return err
	}
	for _, l := range lines {
		fmt.Fprintln(os.Stdout, l)
	}
	return nil
}
