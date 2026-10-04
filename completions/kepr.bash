# Bash completion for kepr.
#
# Install location:
#   /usr/share/bash-completion/completions/kepr
#
# Features:
#   - verbs:   set / get / list / ls / delete / rm / check
#   - flags:   context-aware per subcommand
#   - values:  --gen-kind => hex | base62 | pass | uuid | words
#   - dynamic: get / delete / rm complete existing credential names via
#              `kepr --json list | jq -r '.credentials[]?.name'`
#
# Zsh users — load via bashcompinit in ~/.zshrc:
#   autoload -U +X bashcompinit && bashcompinit
#   source /usr/share/bash-completion/completions/kepr

_kepr_names() {
    # Best-effort — silent if jq is missing or the daemon is unreachable.
    command -v jq >/dev/null 2>&1 || return
    kepr --json list 2>/dev/null \
        | jq -r '.credentials[]?.name' 2>/dev/null
}

_kepr() {
    local cur prev words cword
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion || return
    else
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local GLOBAL_FLAGS='--json --color --no-color --help --version'
    local CMDS='set get list ls delete rm check exec env doctor rotate lock unlock status audit-verify sync-push sync-pull fido2-register fido2-list agent mcp panic leaked totp inject scan copy history restore usage health import discover ssh ssh-agent'

    # Flag-argument completion must come first: if $prev is a flag that
    # takes a value, $cur is that value and we never want to offer verbs
    # or other flag names.
    case "$prev" in
        --value|-v)
            # Free-form secret value; no suggestion.
            return ;;
        --gen-kind)
            COMPREPLY=( $(compgen -W 'hex base62 pass uuid words' -- "$cur") )
            return ;;
    esac

    # Find the first non-flag token after argv[0] — that's the subcommand.
    local i cmd=''
    for ((i = 1; i < cword; i++)); do
        case "${words[i]}" in
            --*) ;;
            *) cmd="${words[i]}"; break ;;
        esac
    done

    # No subcommand yet: complete verbs (or global flags if the user is
    # typing `-...`).
    if [[ -z "$cmd" ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=( $(compgen -W "$GLOBAL_FLAGS" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "$CMDS" -- "$cur") )
        fi
        return
    fi

    # Subcommand chosen — offer flags or positional (credential name).
    case "$cmd" in
        set)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W \
                    '--generate -g --value -v --gen-kind --json --color --no-color' \
                    -- "$cur") )
            fi
            ;;
        get)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W \
                    '--quiet -q --export -e --json --color --no-color' \
                    -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$(_kepr_names)" -- "$cur") )
            fi
            ;;
        delete|rm)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W \
                    '--force -f --json --color --no-color' \
                    -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$(_kepr_names)" -- "$cur") )
            fi
            ;;
        list|ls|check)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W '--json --color --no-color' -- "$cur") )
            fi
            ;;
    esac
}

complete -F _kepr kepr
