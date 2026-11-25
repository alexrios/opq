package main

import (
	"fmt"
	"io"
	"os"
)

type CompletionCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, fish)."`
}

func (c *CompletionCmd) Run() error {
	return runCompletion(c.Shell, os.Stdout)
}

func runCompletion(shell string, w io.Writer) error {
	script, err := completionScript(shell)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, script)
	return err
}

func completionScript(shell string) (string, error) {
	switch shell {
	case "bash":
		return completionBashScript, nil
	case "zsh":
		return completionZshScript, nil
	case "fish":
		return completionFishScript, nil
	default:
		return "", fmt.Errorf("unsupported shell %q (want bash, zsh, or fish)", shell)
	}
}

const completionBashScript = `# opq bash completion
# Enable in your current shell:
#   source <(opq completion bash)
# Or persist in bash-completion's user directory:
#   opq completion bash > "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/opq"

_opq_secret_names() {
    opq list 2>/dev/null | cut -f1
}

_opq_completions() {
    local cur prev cmd i
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local commands="set get list info delete revoke prune exec audit doctor completion mcp"
    local global_flags="--help --version"

    cmd=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            --)
                # After -- in 'opq exec', fall back to default command/file completion.
                return 0
                ;;
            -*)
                ;;
            *)
                if [[ -z "$cmd" ]]; then
                    cmd="${COMP_WORDS[i]}"
                fi
                ;;
        esac
    done

    # Flag argument completions
    case "$prev" in
        --sandbox)
            COMPREPLY=( $(compgen -W "none net full" -- "$cur") )
            return 0
            ;;
        --status)
            COMPREPLY=( $(compgen -W "all active expired revoked pending" -- "$cur") )
            return 0
            ;;
        --caller)
            COMPREPLY=( $(compgen -W "cli mcp" -- "$cur") )
            return 0
            ;;
        --action)
            COMPREPLY=( $(compgen -W "set get delete revoke prune list exec_inject mcp_run audit_tail redaction_disabled network_allowed denied" -- "$cur") )
            return 0
            ;;
        --secret)
            COMPREPLY=( $(compgen -W "$(_opq_secret_names)" -- "$cur") )
            return 0
            ;;
        --ttl|--tail|-n|--env|-e)
            return 0
            ;;
    esac

    if [[ -z "$cmd" ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=( $(compgen -W "$global_flags" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        fi
        return 0
    fi

    if [[ "$cur" == -* ]]; then
        local flags=""
        case "$cmd" in
            set)
                flags="--ttl --keep-ttl --no-clobber --trim --help"
                ;;
            get)
                flags="--plaintext --help"
                ;;
            list)
                flags="--long -l --json --status --help"
                ;;
            info)
                flags="--json --help"
                ;;
            delete|revoke|completion|mcp)
                flags="--help"
                ;;
            prune)
                flags="--dry-run --include-revoked --help"
                ;;
            exec)
                flags="--env -e --sandbox --no-redact --help"
                ;;
            audit)
                flags="--tail -n --all --json --caller --action --secret --help"
                ;;
            doctor)
                flags="--json --help"
                ;;
        esac
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
        return 0
    fi

    case "$cmd" in
        set|get|info|delete|revoke)
            COMPREPLY=( $(compgen -W "$(_opq_secret_names)" -- "$cur") )
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            ;;
    esac
    return 0
}

complete -o default -F _opq_completions opq
`

const completionZshScript = `#compdef opq
# opq zsh completion
# Enable in your current shell:
#   eval "$(opq completion zsh)"
# Or save to a directory in your $fpath as _opq:
#   opq completion zsh > "${fpath[1]}/_opq"

_opq_secret_names() {
    local -a secrets
    secrets=(${(f)"$(opq list 2>/dev/null | cut -f1)"})
    if (( ${#secrets[@]} > 0 )); then
        _describe -t secrets 'secret' secrets
    fi
}

_opq() {
    local context state state_descr line
    typeset -A opt_args

    local -a commands
    commands=(
        'set:Store a secret from stdin or hidden TTY prompt'
        'get:Print a secret to stdout (human-gated with --plaintext)'
        'list:List secret names and TTL/revocation status'
        'info:Show metadata and status for a single secret'
        'delete:Delete one or more secrets and metadata records'
        'revoke:Wipe a secret value and leave a revoked tombstone'
        'prune:Delete expired secrets'
        'exec:Run a command with secrets injected as environment variables'
        'audit:Show recent audit-log entries'
        'doctor:Check keyring, sandbox, audit log, and policy health'
        'completion:Generate shell completion script'
        'mcp:Run as a Model Context Protocol server over stdio'
    )

    _arguments -C \
        '(- *)'{-h,--help}'[Show context-sensitive help]' \
        '(- *)--version[Print the opq version and exit]' \
        '1:command:->command' \
        '*::arg:->args'

    case "$state" in
        command)
            _describe -t commands 'opq command' commands
            ;;
        args)
            case "$line[1]" in
                set)
                    _arguments \
                        '--ttl[Optional time-to-live (e.g. 24h, 90m, 7d, 2w)]:duration:' \
                        '--keep-ttl[Preserve existing unexpired TTL]' \
                        '--no-clobber[Refuse to overwrite an existing live secret]' \
                        '--trim[Strip trailing newline on piped stdin]' \
                        '--help[Show help]' \
                        '1:secret:_opq_secret_names'
                    ;;
                get)
                    _arguments \
                        '--plaintext[Print secret value (requires OPQ_I_AM_HUMAN=1 and TTY confirmation)]' \
                        '--help[Show help]' \
                        '1:secret:_opq_secret_names'
                    ;;
                list)
                    _arguments \
                        '(-l --long)'{-l,--long}'[Show detailed status and timestamps]' \
                        '--json[Output as JSON]' \
                        '--status[Filter by status]:status:(all active expired revoked pending)' \
                        '--help[Show help]'
                    ;;
                info)
                    _arguments \
                        '--json[Output secret metadata as JSON]' \
                        '--help[Show help]' \
                        '1:secret:_opq_secret_names'
                    ;;
                delete)
                    _arguments \
                        '--help[Show help]' \
                        '*:secret:_opq_secret_names'
                    ;;
                revoke)
                    _arguments \
                        '--help[Show help]' \
                        '1:secret:_opq_secret_names'
                    ;;
                prune)
                    _arguments \
                        '--dry-run[Show what would be pruned without deleting]' \
                        '--include-revoked[Also remove REVOKED tombstones]' \
                        '--help[Show help]'
                    ;;
                exec)
                    _arguments \
                        '*'{-e,--env}'[Inject secret as env var (VAR=secret_name or VAR)]:env:' \
                        '--sandbox[Subprocess sandbox profile]:profile:(none net full)' \
                        '--no-redact[Disable output redaction (human-gated)]' \
                        '--help[Show help]' \
                        '*::command:_normal'
                    ;;
                audit)
                    _arguments \
                        '(-n --tail)'{-n,--tail}'[Number of trailing entries to show]:count:' \
                        '--all[Show all available entries]' \
                        '--json[Output raw JSONL]' \
                        '--caller[Filter by caller]:caller:(cli mcp)' \
                        '--action[Filter by audit action]:action:(set get delete revoke prune list exec_inject mcp_run audit_tail redaction_disabled network_allowed denied)' \
                        '--secret[Filter by secret name]:secret:_opq_secret_names' \
                        '--help[Show help]'
                    ;;
                doctor)
                    _arguments \
                        '--json[Output health check results as JSON]' \
                        '--help[Show help]'
                    ;;
                completion)
                    _arguments \
                        '--help[Show help]' \
                        '1:shell:(bash zsh fish)'
                    ;;
                mcp)
                    _arguments \
                        '--help[Show help]'
                    ;;
            esac
            ;;
    esac
}

if [[ "$funcstack[1]" == "_opq" ]]; then
    _opq "$@"
else
    compdef _opq opq
fi
`

const completionFishScript = `# opq fish completion
# Enable in your current shell:
#   opq completion fish | source
# Or persist in fish's completions directory:
#   opq completion fish > ~/.config/fish/completions/opq.fish

function __opq_secret_names
    opq list 2>/dev/null | cut -f1
end

function __opq_no_subcommand
    not __fish_seen_subcommand_from set get list info delete revoke prune exec audit doctor completion mcp
end

# Global flags
complete -c opq -n __opq_no_subcommand -l help -d 'Show context-sensitive help'
complete -c opq -n __opq_no_subcommand -l version -d 'Print the opq version and exit'

# Subcommands
complete -c opq -f -n __opq_no_subcommand -a set -d 'Store a secret from stdin or hidden TTY prompt'
complete -c opq -f -n __opq_no_subcommand -a get -d 'Print a secret to stdout (human-gated with --plaintext)'
complete -c opq -f -n __opq_no_subcommand -a list -d 'List secret names and TTL/revocation status'
complete -c opq -f -n __opq_no_subcommand -a info -d 'Show metadata and status for a single secret'
complete -c opq -f -n __opq_no_subcommand -a delete -d 'Delete one or more secrets and metadata records'
complete -c opq -f -n __opq_no_subcommand -a revoke -d 'Wipe a secret value and leave a revoked tombstone'
complete -c opq -f -n __opq_no_subcommand -a prune -d 'Delete expired secrets'
complete -c opq -f -n __opq_no_subcommand -a exec -d 'Run a command with secrets injected as environment variables'
complete -c opq -f -n __opq_no_subcommand -a audit -d 'Show recent audit-log entries'
complete -c opq -f -n __opq_no_subcommand -a doctor -d 'Check keyring, sandbox, audit log, and policy health'
complete -c opq -f -n __opq_no_subcommand -a completion -d 'Generate shell completion script'
complete -c opq -f -n __opq_no_subcommand -a mcp -d 'Run as a Model Context Protocol server over stdio'

# set
complete -c opq -f -n '__fish_seen_subcommand_from set' -l ttl -r -d 'Optional time-to-live (e.g. 24h, 90m, 7d, 2w)'
complete -c opq -f -n '__fish_seen_subcommand_from set' -l keep-ttl -d 'Preserve existing unexpired TTL'
complete -c opq -f -n '__fish_seen_subcommand_from set' -l no-clobber -d 'Refuse to overwrite an existing live secret'
complete -c opq -f -n '__fish_seen_subcommand_from set' -l trim -d 'Strip trailing newline on piped stdin'
complete -c opq -f -n '__fish_seen_subcommand_from set' -l help -d 'Show help'
complete -c opq -f -n '__fish_seen_subcommand_from set' -a '(__opq_secret_names)'

# get
complete -c opq -f -n '__fish_seen_subcommand_from get' -l plaintext -d 'Print secret value (requires OPQ_I_AM_HUMAN=1 and TTY confirmation)'
complete -c opq -f -n '__fish_seen_subcommand_from get' -l help -d 'Show help'
complete -c opq -f -n '__fish_seen_subcommand_from get' -a '(__opq_secret_names)'

# list
complete -c opq -f -n '__fish_seen_subcommand_from list' -s l -l long -d 'Show detailed status and timestamps'
complete -c opq -f -n '__fish_seen_subcommand_from list' -l json -d 'Output as JSON'
complete -c opq -f -n '__fish_seen_subcommand_from list' -l status -x -a 'all active expired revoked pending' -d 'Filter by status'
complete -c opq -f -n '__fish_seen_subcommand_from list' -l help -d 'Show help'

# info
complete -c opq -f -n '__fish_seen_subcommand_from info' -l json -d 'Output secret metadata as JSON'
complete -c opq -f -n '__fish_seen_subcommand_from info' -l help -d 'Show help'
complete -c opq -f -n '__fish_seen_subcommand_from info' -a '(__opq_secret_names)'

# delete
complete -c opq -f -n '__fish_seen_subcommand_from delete' -l help -d 'Show help'
complete -c opq -f -n '__fish_seen_subcommand_from delete' -a '(__opq_secret_names)'

# revoke
complete -c opq -f -n '__fish_seen_subcommand_from revoke' -l help -d 'Show help'
complete -c opq -f -n '__fish_seen_subcommand_from revoke' -a '(__opq_secret_names)'

# prune
complete -c opq -f -n '__fish_seen_subcommand_from prune' -l dry-run -d 'Show what would be pruned without deleting'
complete -c opq -f -n '__fish_seen_subcommand_from prune' -l include-revoked -d 'Also remove REVOKED tombstones'
complete -c opq -f -n '__fish_seen_subcommand_from prune' -l help -d 'Show help'

# exec
complete -c opq -n '__fish_seen_subcommand_from exec' -s e -l env -r -d 'Inject secret as env var (VAR=secret_name or VAR)'
complete -c opq -n '__fish_seen_subcommand_from exec' -l sandbox -x -a 'none net full' -d 'Subprocess sandbox profile'
complete -c opq -n '__fish_seen_subcommand_from exec' -l no-redact -d 'Disable output redaction (human-gated)'
complete -c opq -n '__fish_seen_subcommand_from exec' -l help -d 'Show help'

# audit
complete -c opq -f -n '__fish_seen_subcommand_from audit' -s n -l tail -r -d 'Number of trailing entries to show'
complete -c opq -f -n '__fish_seen_subcommand_from audit' -l all -d 'Show all available entries'
complete -c opq -f -n '__fish_seen_subcommand_from audit' -l json -d 'Output raw JSONL'
complete -c opq -f -n '__fish_seen_subcommand_from audit' -l caller -x -a 'cli mcp' -d 'Filter by caller'
complete -c opq -f -n '__fish_seen_subcommand_from audit' -l action -x -a 'set get delete revoke prune list exec_inject mcp_run audit_tail redaction_disabled network_allowed denied' -d 'Filter by audit action'
complete -c opq -f -n '__fish_seen_subcommand_from audit' -l secret -x -a '(__opq_secret_names)' -d 'Filter by secret name'
complete -c opq -f -n '__fish_seen_subcommand_from audit' -l help -d 'Show help'

# doctor
complete -c opq -f -n '__fish_seen_subcommand_from doctor' -l json -d 'Output health check results as JSON'
complete -c opq -f -n '__fish_seen_subcommand_from doctor' -l help -d 'Show help'

# completion
complete -c opq -f -n '__fish_seen_subcommand_from completion' -l help -d 'Show help'
complete -c opq -f -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'

# mcp
complete -c opq -f -n '__fish_seen_subcommand_from mcp' -l help -d 'Show help'
`
