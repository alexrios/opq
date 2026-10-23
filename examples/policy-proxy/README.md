# Fixed-operation MCP policy proxy

This opt-in example exposes only operations approved by the operator. An agent chooses
an operation name and supplies `{}`. It cannot choose a command, arguments, secret
mapping, timeout, network permission, or isolation profile. The proxy privately calls
`opq mcp` and returns only `succeeded` and `timed_out` booleans. Upstream output,
errors, metadata, and secret names are never forwarded.

The supplied policy approves no operations. The example is a deployment wrapper;
it does not add policy files to the opq CLI.

## Build and configure

From the repository root:

```sh
go build -o /tmp/opq-policy-proxy ./examples/policy-proxy
go test -race ./examples/policy-proxy
```

An operator installs the binary and a policy outside every directory the agent can
modify. For example, on a Unix host with an operator-managed `/usr/local/libexec`:

```sh
sudo install -d -m 0755 /usr/local/libexec /etc/opq-policy-proxy
sudo install -o root -m 0755 /tmp/opq-policy-proxy /usr/local/libexec/opq-policy-proxy
sudo install -o root -m 0644 examples/policy-proxy/policy.example.json /etc/opq-policy-proxy/policy.json
```

Set `opq` in the policy to the absolute path of a trusted patched opq binary. Protect
that binary, every approved program, their parent directories, scripts, libraries,
and configuration from agent writes. The JSON stores names and fixed arguments,
never credential values. Provision credentials separately through the operator's
keyring workflow.

Run the proxy as the trusted principal that can use the intended keyring session:

```sh
/usr/local/libexec/opq-policy-proxy --config /etc/opq-policy-proxy/policy.json
```

Register that command as the agent's stdio MCP server. Do not also expose the upstream
`opq mcp`, unrestricted `opq exec`, or another route to the keyring. An agent with
unrestricted shell access as the same OS principal can bypass this wrapper. Separate
the agent's OS permissions and tools from the trusted proxy's authority when that
threat is in scope. A file permission check alone cannot establish that separation.

## Approve a fixed operation

The operator can replace the empty `operations` array with a reviewed operation. This
example performs a local smoke check and uses no credentials:

```json
{
  "opq": "/usr/local/bin/opq",
  "operations": [
    {
      "name": "local_probe",
      "command": "/usr/bin/true",
      "args": [],
      "env": {},
      "timeout_seconds": 5,
      "allow_network": false,
      "isolation": "full"
    }
  ]
}
```

The agent sees only the `local_probe` tool and calls it with `{}`. For an authenticated
operation, use a protected consumer program that reads the credential directly from
its environment, then set an exact mapping such as `"env": {"API_TOKEN":"provider_token"}`.
Keep endpoint and request behavior fixed in that reviewed program or its protected
configuration. Secret names are references; never put values in `args` or the policy.

The parser rejects unknown and duplicate JSON fields, duplicate operation names,
relative executable paths, invalid environment mappings, and unsupported limits or
isolation combinations. `run_with_secrets`, `list_secrets`, and `audit_tail` are reserved
names. Calls with any arguments are rejected by both the closed input schema and a
runtime check. Two operations can run concurrently; excess calls fail immediately.
Each operation has its own 1–600 second deadline. Upstream initialization is bounded
at ten seconds. Client EOF, connection failure, and SIGTERM cancel active operation
requests before the server waits for shutdown. The private upstream then receives stdin
EOF so opq can cancel and reap consuming subprocesses; the SDK has a bounded signal
and kill fallback if that upstream does not exit.

## Review the consuming program

A fixed executable and argv do not validate the program's behavior. Network-enabled
operations require `"isolation":"net"` and remain potential egress channels. Review
redirect handling, proxy environment/configuration, DNS and TLS validation, native
configuration loading, plugins, subprocess execution, and writable inputs. Disable
redirects and ambient proxies where the workflow does not require them. The proxy
fixes permission to use the network; it does not implement a destination firewall.

Avoid shell snippets that expand credentials into argv, even with fixed command text.
Use native environment-based authentication in the consuming program. A permitted
script that reads agent-writable files can restore arbitrary behavior, so protect its
inputs or give it a narrower sandbox.

The two returned booleans and request timing still disclose coarse status. Approved
operations must be reviewed to ensure that the status itself does not encode secret
material. This example intentionally provides no raw-output escape hatch.
