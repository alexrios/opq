package main

import (
	"fmt"
	"os"
)

type AuditCmd struct {
	Tail int `name:"tail" short:"n" default:"20" help:"Number of trailing entries to show. 0 = all."`
}

func (c *AuditCmd) Run() error {
	lines, err := tailAudit(c.Tail)
	if err != nil {
		return err
	}
	for _, l := range lines {
		fmt.Fprintln(os.Stdout, l)
	}
	return nil
}
