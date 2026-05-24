package main

import (
	"context"
	"fmt"
	"os"
)

type ListCmd struct{}

func (c *ListCmd) Run() error {
	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	names, err := backend.List(ctx)
	if err != nil {
		return err
	}
	_ = AppendAudit(AuditEvent{Action: ActionList, Caller: callerTag()})
	for _, n := range names {
		fmt.Fprintln(os.Stdout, n)
	}
	return nil
}
