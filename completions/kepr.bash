# Bash completion for kepr.
#
# Install locations:
#   /usr/share/bash-completion/completions/kepr (system; registers both binaries)
#   ~/.local/share/bash-completion/completions/kepr (user-local)
#   ~/.local/share/bash-completion/completions/kepr-daemon (same script)
#
# Features:
#   - verbs:   every `kepr` activity plus `help`
#   - flags:   context-aware; bare names and `--`-prefixed forms
#   - values:  gen-kind / --gen-kind => hex | base62 | pass | uuid
#   - daemon:  `kepr-daemon` user-mode and help completion
#   - dynamic: get / set / delete / rm / rotate / sync-* offer stored names
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

_kepr_compgen() {
    mapfile -t COMPREPLY < <(compgen -W "$1" -- "$2")
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

    local GLOBAL_BARE='json color no-color version help'
    local GLOBAL_DASHED='--json --color --no-color --version --help -h'
    local CMDS='help set get list ls delete rm check lock unlock status exec doctor env rotate audit-verify sync-push sync-pull fido2-register fido2-list protect-agent'
    local i cmd=''
    for ((i = 1; i < cword; i++)); do
        case "${words[i]}" in
            json|--json|color|--color|no-color|--no-color|version|--version) ;;
            --*) ;;
            *) cmd="${words[i]}"; break ;;
        esac
    done

    if [[ -n "$cmd" && "$prev" != "$cmd" ]]; then
        case "$prev" in
            value|--value|-v|env|--env|memfd|--memfd|manifest|--manifest|hook|--hook|url|--url|ttl|--ttl)
                return ;;
            gen-kind|--gen-kind)
                _kepr_compgen 'hex base62 pass uuid' "$cur"
                return ;;
        esac
    fi

    if [[ -z "$cmd" ]]; then
        if [[ "$cur" == -* ]]; then
            _kepr_compgen "$GLOBAL_DASHED" "$cur"
        else
            _kepr_compgen "$CMDS $GLOBAL_BARE" "$cur"
        fi
        return
    fi

    if [[ "$prev" == "$cmd" ]]; then
        case "$cmd" in
            help)
                _kepr_compgen "$CMDS" "$cur" ;;
            set|get|delete|rm|rotate|sync-push|sync-pull|protect-agent)
                _kepr_compgen "help $(_kepr_names)" "$cur" ;;
            exec)
                _kepr_compgen \
                    'help env --env memfd --memfd manifest --manifest json --json color --color no-color --no-color --' \
                    "$cur" ;;
            env)
                _kepr_compgen \
                    'help env --env manifest --manifest json --json color --color no-color --no-color' \
                    "$cur" ;;
            *)
                _kepr_compgen "help json --json color --color no-color --no-color" "$cur" ;;
        esac
        return
    fi

    case "$cmd" in
        set)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen \
                    '--generate -g --value -v --gen-kind --ttl --requires-consent --requires-fido2 --stdin --json --color --no-color --help' \
                    "$cur"
            else
                _kepr_compgen \
                    'generate value -v gen-kind ttl requires-consent requires-fido2 stdin json color no-color help' \
                    "$cur"
            fi
            ;;
        get)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen '--quiet -q --export -e --json --color --no-color --help' "$cur"
            else
                _kepr_compgen "$(_kepr_names) quiet export json color no-color help" "$cur"
            fi
            ;;
        delete|rm)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen '--force -f --json --color --no-color --help' "$cur"
            else
                _kepr_compgen "$(_kepr_names) force json color no-color help" "$cur"
            fi
            ;;
        list|ls|check|lock|unlock|status|doctor|audit-verify|fido2-list|fido2-register)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen '--json --color --no-color --help' "$cur"
            else
                _kepr_compgen 'json color no-color help' "$cur"
            fi
            ;;
        exec|env)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen '--env --memfd --manifest --json --color --no-color --help --' "$cur"
            else
                _kepr_compgen 'env memfd manifest json color no-color help --' "$cur"
            fi
            ;;
        rotate)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen '--hook --gen-kind --json --color --no-color --help' "$cur"
            else
                _kepr_compgen 'hook gen-kind json color no-color help' "$cur"
            fi
            ;;
        sync-push|sync-pull)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen '--url --json --color --no-color --help' "$cur"
            else
                _kepr_compgen 'url json color no-color help' "$cur"
            fi
            ;;
        protect-agent)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen '--help --' "$cur"
            else
                _kepr_compgen 'help --' "$cur"
            fi
            ;;
    esac
}

_kepr_daemon() {
    local cur prev
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion || return
    else
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
    fi
    if [[ "$prev" == "user" || "$prev" == "--user" ]]; then
        return
    fi
    if [[ "$cur" == -* ]]; then
        _kepr_compgen '--user --help -h' "$cur"
    else
        _kepr_compgen 'user help --user --help' "$cur"
    fi
}

complete -F _kepr kepr
complete -F _kepr_daemon kepr-daemon
