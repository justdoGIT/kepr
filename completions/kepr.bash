# shellcheck shell=bash
# Bash completion for kepr and kepr-daemon.
#
# Standard Linux Install Locations:
#   System application folder: /usr/share/bash-completion/completions/kepr
#                              /usr/share/bash-completion/completions/kepr-daemon
#   User application folder:   ~/.local/share/bash-completion/completions/kepr
#                              ~/.local/share/bash-completion/completions/kepr-daemon
#
# Features:
#   - Full subcommand hierarchy and multi-variable positional depth
#   - Context-aware flag completion (e.g. --for, --workspace, --hook, --size, --preset, --type)
#   - Dynamic completion of stored keys, sealed keys, workspace sessions, folders, and tags
#   - Comma-separated credential list completion for --env / --memfd
#   - Command and file argument completion following '--'
#   - Global options and profile handling (--profile NAME ...)
#   - kepr-daemon user-mode and socket completion
#
# Zsh users — load via bashcompinit in ~/.zshrc:
#   autoload -U +X bashcompinit && bashcompinit
#   source ~/.local/share/bash-completion/completions/kepr

_kepr_compgen() {
    mapfile -t COMPREPLY < <(compgen -W "$1" -- "$2")
}

_kepr_filedir() {
    local cur_word="$1"
    if declare -F _filedir >/dev/null 2>&1; then
        _filedir
    else
        mapfile -t COMPREPLY < <(compgen -f -- "$cur_word")
    fi
}

_kepr_dirs() {
    local cur_word="$1"
    if declare -F _filedir >/dev/null 2>&1; then
        _filedir -d
    else
        mapfile -t COMPREPLY < <(compgen -d -- "$cur_word")
    fi
}

_kepr_names() {
    command -v jq >/dev/null 2>&1 || return
    kepr --json list 2>/dev/null \
        | jq -r '.credentials[]?.name' 2>/dev/null
}

_kepr_sealed_names() {
    kepr agent ls 2>/dev/null | awk 'NF > 0 && $1 !~ /^[·]/ {print $1}'
}

_kepr_workspace_sessions() {
    local ws_dir="${XDG_STATE_HOME:-$HOME/.local/state}/kepr/workspace"
    if [[ -d "$ws_dir" ]]; then
        find "$ws_dir" -maxdepth 1 -mindepth 1 -type d -exec basename {} \; 2>/dev/null
    fi
}

_kepr_trash_names() {
    kepr trash ls 2>/dev/null | awk 'NF > 0 && $1 !~ /^[·]/ {print $1}'
}

_kepr_folders() {
    command -v jq >/dev/null 2>&1 || return
    kepr --json list 2>/dev/null \
        | jq -r '.credentials[]?.folder // empty' 2>/dev/null | sort -u
}

_kepr_tags() {
    command -v jq >/dev/null 2>&1 || return
    kepr --json list 2>/dev/null \
        | jq -r '.credentials[]?.tags[]? // empty' 2>/dev/null | sort -u
}

_kepr_csv_names() {
    local cur_word="$1"
    local prefix=""
    local suffix="$cur_word"
    if [[ "$cur_word" == *,* ]]; then
        prefix="${cur_word%,*},"
        suffix="${cur_word##*,}"
    fi
    local names
    names="$(_kepr_names)"
    mapfile -t COMPREPLY < <(compgen -W "$names" -P "$prefix" -- "$suffix")
}

_kepr() {
    local cur prev words cword
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion -n : || return
    else
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local GLOBAL_BARE='json color no-color version help'
    local GLOBAL_DASHED='--json --color --no-color --version --help -h --profile'
    local CMDS='help set get list ls delete rm check lock unlock status exec doctor env rotate audit-verify sync-push sync-pull fido2-register fido2-list protect-agent panic mcp agent totp inject scan copy ssh ssh-agent history restore usage health import discover leaked record share recovery-kit workspace privacy endpoint vault recovery-key tag mv search trash ln dupes attach resolve strength device emergency break-glass escrow sync export folder quorum policy report audit alerts anomaly approvals canary aws github-app gcp grant checkout checkin shell ui systemd-cred keyring exe pki mount reauth batch serve passwd login-unlock pam-unlock pam-passwd secret-service secret'
    local HARNESSES='claude codex grok-cli aider omp grok gemini opencode cursor copilot'
    local PROVIDERS='anthropic openai fireworks moonshot venice agentrouter selora xai google mistral deepseek groq openrouter github git stripe npm gcloud docker cloudflare aws-bedrock azure-openai'

    # Delegate command arguments after '--'
    local dash_idx=-1
    local k
    for ((k = 1; k < cword; k++)); do
        if [[ "${words[k]}" == "--" ]]; then
            dash_idx=$k
            break
        fi
    done

    if (( dash_idx != -1 )); then
        if (( cword == dash_idx + 1 )); then
            mapfile -t COMPREPLY < <(compgen -c -- "$cur")
        else
            _kepr_filedir "$cur"
        fi
        return
    fi

    # Context-aware flag values
    case "$prev" in
        --profile)
            return ;;
        --workspace|--dir|--output|-o)
            _kepr_dirs "$cur"
            return ;;
        --hook|-i|--input|--manifest|--file|--policy)
            _kepr_filedir "$cur"
            return ;;
        --socket)
            _kepr_filedir "$cur"
            return ;;
        --for)
            _kepr_compgen "$PROVIDERS" "$cur"
            return ;;
        --workspace-session)
            _kepr_compgen "$(_kepr_workspace_sessions)" "$cur"
            return ;;
        --security-preset|--preset)
            _kepr_compgen "private-cloud local-only" "$cur"
            return ;;
        --gen-kind|gen-kind)
            _kepr_compgen "hex base62 pass uuid" "$cur"
            return ;;
        --type)
            _kepr_compgen "ed25519 ecdsa" "$cur"
            return ;;
        --format)
            _kepr_compgen "auto dotenv json csv yaml keepass" "$cur"
            return ;;
        --size)
            _kepr_compgen "32 64 128 256 512 1024" "$cur"
            return ;;
        --env|env|--memfd|memfd)
            _kepr_csv_names "$cur"
            return ;;
        --merge)
            _kepr_compgen "$(_kepr_names)" "$cur"
            return ;;
        --folder)
            _kepr_compgen "$(_kepr_folders)" "$cur"
            return ;;
        --tag)
            _kepr_compgen "$(_kepr_tags)" "$cur"
            return ;;
        --approve|--ttl|ttl|--clear|--days|--port|--max-requests|--max-tokens|--rate|--max-requests-day|--max-tokens-day|-n|--comment|--prefix|--label|--collection|--host|--version|--stage|value|--value|-v)
            return ;;
    esac

    # Locate top-level command
    local i cmd='' cmd_idx=-1
    for ((i = 1; i < cword; i++)); do
        case "${words[i]}" in
            --profile)
                (( i++ )) ;;
            --profile=*)
                ;;
            json|--json|color|--color|no-color|--no-color|version|--version)
                ;;
            --*)
                ;;
            *)
                cmd="${words[i]}"
                cmd_idx=$i
                break
                ;;
        esac
    done

    # If no command chosen yet
    if [[ -z "$cmd" ]]; then
        if [[ "$cur" == -* ]]; then
            _kepr_compgen "$GLOBAL_DASHED" "$cur"
        else
            _kepr_compgen "$CMDS $GLOBAL_BARE" "$cur"
        fi
        return
    fi

    # Collect positional arguments after cmd up to cword
    local -a pos=()
    local j skip_next=0
    for ((j = cmd_idx + 1; j < cword; j++)); do
        if (( skip_next )); then
            skip_next=0
            continue
        fi
        case "${words[j]}" in
            --for|--workspace|--workspace-session|--dir|--output|-o|--hook|-i|--input|--manifest|--file|--policy|--socket|--security-preset|--preset|--gen-kind|gen-kind|--type|--format|--size|--env|env|--memfd|memfd|--merge|--folder|--tag|--approve|--ttl|ttl|--clear|--days|--port|--max-requests|--max-tokens|--rate|--max-requests-day|--max-tokens-day|-n|--comment|--prefix|--label|--collection|--host|--version|--stage|value|--value|-v|url|--url)
                skip_next=1
                ;;
            --*)
                ;;
            *)
                pos+=("${words[j]}")
                ;;
        esac
    done

    local pos_count="${#pos[@]}"

    case "$cmd" in
        help)
            _kepr_compgen "$CMDS" "$cur"
            ;;

        agent)
            if (( pos_count == 0 )); then
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "add run install doctor shim ls list revoke adopt add-cloudflare help" "$cur"
                fi
                return
            fi
            local subcmd="${pos[0]}"
            case "$subcmd" in
                add)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$(_kepr_names)" "$cur"
                    else
                        _kepr_compgen "--for --stdin --from-clipboard --requires-consent --json --color --no-color --help" "$cur"
                    fi
                    ;;
                run)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$HARNESSES" "$cur"
                    else
                        _kepr_compgen "--workspace --workspace-session --window --security-preset --compatibility --no-sandbox --strict-sandbox --isolate-net --port --max-requests --max-tokens --rate --max-requests-day --max-tokens-day --json --color --no-color --help --" "$cur"
                    fi
                    ;;
                install)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$HARNESSES" "$cur"
                    else
                        _kepr_compgen "--port --json --color --no-color --help" "$cur"
                    fi
                    ;;
                doctor)
                    _kepr_compgen "--port --json --color --no-color --help" "$cur"
                    ;;
                shim)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$HARNESSES" "$cur"
                    else
                        _kepr_compgen "--dir --remove --json --color --no-color --help" "$cur"
                    fi
                    ;;
                revoke)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$(_kepr_sealed_names)" "$cur"
                    else
                        _kepr_compgen "--json --color --no-color --help" "$cur"
                    fi
                    ;;
                adopt)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$HARNESSES" "$cur"
                    fi
                    ;;
                add-cloudflare)
                    _kepr_compgen "--account-id --gateway --token --json --color --no-color --help" "$cur"
                    ;;
                ls|list)
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                    ;;
            esac
            ;;

        workspace)
            if (( pos_count == 0 )); then
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "prepare review export help" "$cur"
                fi
                return
            fi
            local ws_sub="${pos[0]}"
            case "$ws_sub" in
                prepare)
                    if (( pos_count == 1 )); then
                        _kepr_dirs "$cur"
                    else
                        _kepr_compgen "--file --json --color --no-color --help" "$cur"
                    fi
                    ;;
                review)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$(_kepr_workspace_sessions)" "$cur"
                    else
                        _kepr_compgen "--json --color --no-color --help" "$cur"
                    fi
                    ;;
                export)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$(_kepr_workspace_sessions)" "$cur"
                    else
                        _kepr_compgen "--approve --output --json --color --no-color --help" "$cur"
                    fi
                    ;;
            esac
            ;;

        vault)
            if (( pos_count == 0 )); then
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "init migrate verify status resize to-files help" "$cur"
                fi
                return
            fi
            case "${pos[0]}" in
                init|resize)
                    _kepr_compgen "--size --json --color --no-color --help" "$cur"
                    ;;
                *)
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                    ;;
            esac
            ;;

        privacy)
            if (( pos_count == 0 )); then
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "init configure status preview help" "$cur"
                fi
                return
            fi
            case "${pos[0]}" in
                init)
                    _kepr_compgen "--preset --json --color --no-color --help" "$cur"
                    ;;
                configure)
                    _kepr_compgen "--stdin --json --color --no-color --help" "$cur"
                    ;;
                *)
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                    ;;
            esac
            ;;

        endpoint)
            if (( pos_count == 0 )); then
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "status scan help" "$cur"
                fi
                return
            fi
            if [[ "${pos[0]}" == "scan" ]]; then
                _kepr_filedir "$cur"
            else
                _kepr_compgen "--json --color --no-color --help" "$cur"
            fi
            ;;

        trash)
            if (( pos_count == 0 )); then
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "ls restore purge help" "$cur"
                fi
                return
            fi
            case "${pos[0]}" in
                restore)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$(_kepr_trash_names)" "$cur"
                    fi
                    ;;
                purge)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$(_kepr_trash_names) --yes" "$cur"
                    else
                        _kepr_compgen "--yes" "$cur"
                    fi
                    ;;
                ls)
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                    ;;
            esac
            ;;

        ssh)
            if (( pos_count == 0 )); then
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "generate import list rotate help" "$cur"
                fi
                return
            fi
            case "${pos[0]}" in
                generate)
                    if (( pos_count > 1 )); then
                        _kepr_compgen "--type --comment --requires-consent --json --color --no-color --help" "$cur"
                    fi
                    ;;
                import)
                    if (( pos_count == 2 )); then
                        _kepr_filedir "$cur"
                    elif (( pos_count > 2 )); then
                        _kepr_compgen "--requires-consent --json --color --no-color --help" "$cur"
                    fi
                    ;;
                rotate)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "$(_kepr_names)" "$cur"
                    else
                        _kepr_compgen "--host --json --color --no-color --help" "$cur"
                    fi
                    ;;
                list)
                    _kepr_compgen "--json --color --no-color --help" "$cur"
                    ;;
            esac
            ;;

        ssh-agent)
            _kepr_compgen "--foreground --socket --help -h" "$cur"
            ;;

        secret-service)
            if (( pos_count == 0 )); then
                _kepr_compgen "run takeover status import log policy restore help" "$cur"
                return
            fi
            case "${pos[0]}" in
                run)
                    _kepr_compgen "--replace --json --color --no-color --help" "$cur" ;;
                takeover)
                    _kepr_compgen "--now --no-import --json --color --no-color --help" "$cur" ;;
                import)
                    _kepr_compgen "--dry-run --overwrite --json --color --no-color --help" "$cur" ;;
                log)
                    _kepr_compgen "-n --json --color --no-color --help" "$cur" ;;
                policy)
                    if (( pos_count == 1 )); then
                        _kepr_compgen "check" "$cur"
                    elif (( pos_count == 2 )); then
                        _kepr_filedir "$cur"
                    fi
                    ;;
                *)
                    _kepr_compgen "--json --color --no-color --help" "$cur" ;;
            esac
            ;;

        secret)
            if (( pos_count == 0 )); then
                _kepr_compgen "store lookup clear search ls help" "$cur"
                return
            fi
            _kepr_compgen "--label --collection --all --secrets" "$cur"
            ;;

        policy)
            if (( pos_count == 0 )); then
                _kepr_compgen "test status reload help" "$cur"
                return
            fi
            if [[ "${pos[0]}" == "test" ]] && (( pos_count == 1 )); then
                _kepr_filedir "$cur"
            fi
            ;;

        recovery-kit)
            if (( pos_count == 0 )); then
                _kepr_compgen "create restore help" "$cur"
            else
                _kepr_compgen "--words --json --color --no-color --help" "$cur"
            fi
            ;;

        recovery-key)
            if (( pos_count == 0 )); then
                _kepr_compgen "enrol unlock help" "$cur"
            elif [[ "${pos[0]}" == "enrol" ]]; then
                _kepr_compgen "--replace --json --color --no-color --help" "$cur"
            else
                _kepr_compgen "--json --color --no-color --help" "$cur"
            fi
            ;;

        login-unlock)
            if (( pos_count == 0 )); then
                _kepr_compgen "on off status help" "$cur"
            elif [[ "${pos[0]}" == "on" ]]; then
                _kepr_compgen "--ssh-agent --json --color --no-color --help" "$cur"
            else
                _kepr_compgen "--json --color --no-color --help" "$cur"
            fi
            ;;

        set)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            else
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--stdin --value -v --generate -g --gen-kind --ttl --requires-consent --requires-fido2 --json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "stdin value generate -g gen-kind ttl requires-consent requires-fido2 json color no-color help" "$cur"
                fi
            fi
            ;;

        get)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            else
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--quiet -q --export -e --json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "quiet export json color no-color help" "$cur"
                fi
            fi
            ;;

        delete|rm)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names) --all" "$cur"
            else
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--force -f --all --yes --json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "force json color no-color help" "$cur"
                fi
            fi
            ;;

        rotate)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            else
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--hook --gen-kind --json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "hook gen-kind json color no-color help" "$cur"
                fi
            fi
            ;;

        history)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            else
                _kepr_compgen "--diff --json --color --no-color --help" "$cur"
            fi
            ;;

        restore)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            else
                _kepr_compgen "--version --json --color --no-color --help" "$cur"
            fi
            ;;

        totp)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            fi
            ;;

        copy)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            else
                _kepr_compgen "--clear --json --color --no-color --help" "$cur"
            fi
            ;;

        leaked)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            else
                _kepr_compgen "--yes -y --rotate --json --color --no-color --help" "$cur"
            fi
            ;;

        mv)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            elif (( pos_count == 1 )); then
                _kepr_compgen "$(_kepr_folders) /" "$cur"
            fi
            ;;

        ln)
            if (( pos_count == 1 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            fi
            ;;

        tag)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            else
                _kepr_compgen "$(_kepr_tags)" "$cur"
            fi
            ;;

        dupes)
            _kepr_compgen "--merge --json --color --no-color --help" "$cur"
            ;;

        exec)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen "--env --memfd --manifest --stage --mask --json --color --no-color --help --" "$cur"
            else
                _kepr_compgen "env memfd manifest stage mask json color no-color help --" "$cur"
            fi
            ;;

        env)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen "--env --manifest --stage --json --color --no-color --help" "$cur"
            else
                _kepr_compgen "env manifest stage json color no-color help" "$cur"
            fi
            ;;

        doctor)
            _kepr_compgen "--verify --json --color --no-color --help" "$cur"
            ;;

        lock)
            _kepr_compgen "--fido2 --json --color --no-color --help" "$cur"
            ;;

        list|ls)
            _kepr_compgen "--tag --folder --json --color --no-color --help" "$cur"
            ;;

        sync-push|sync-pull)
            if (( pos_count == 0 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            else
                if [[ "$cur" == -* ]]; then
                    _kepr_compgen "--url --json --color --no-color --help" "$cur"
                else
                    _kepr_compgen "url json color no-color help" "$cur"
                fi
            fi
            ;;

        inject)
            _kepr_compgen "-i --input -o --output --allow-disk --json --color --no-color --help" "$cur"
            ;;

        scan)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen "--staged --json --color --no-color --help" "$cur"
            else
                _kepr_filedir "$cur"
            fi
            ;;

        import)
            if (( pos_count == 0 )); then
                _kepr_filedir "$cur"
            else
                _kepr_compgen "--format --prefix --seal --overwrite --yes -y --json --color --no-color --help" "$cur"
            fi
            ;;

        discover)
            _kepr_compgen "--seal --overwrite --yes -y --json --color --no-color --help" "$cur"
            ;;

        protect-agent)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen "--help --" "$cur"
            else
                _kepr_compgen "help --" "$cur"
            fi
            ;;

        record)
            if (( pos_count == 0 )); then
                _kepr_compgen "add show get types help" "$cur"
            elif [[ "${pos[0]}" == "show" || "${pos[0]}" == "get" ]] && (( pos_count == 1 )); then
                _kepr_compgen "$(_kepr_names)" "$cur"
            fi
            ;;

        share)
            if (( pos_count == 0 )); then
                _kepr_compgen "key send receive help" "$cur"
            fi
            ;;

        sync)
            if (( pos_count == 0 )); then
                _kepr_compgen "status push pull help" "$cur"
            fi
            ;;

        check|unlock|status|audit-verify|fido2-list|passwd|panic|mcp)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen "--json --color --no-color --help" "$cur"
            else
                _kepr_compgen "json color no-color help" "$cur"
            fi
            ;;

        *)
            if [[ "$cur" == -* ]]; then
                _kepr_compgen "--json --color --no-color --help" "$cur"
            else
                _kepr_compgen "json color no-color help" "$cur"
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

    case "$prev" in
        --socket)
            _kepr_filedir "$cur"
            return ;;
        --profile|user|--user)
            return ;;
    esac

    if [[ "$cur" == -* ]]; then
        _kepr_compgen "--user --profile --socket --verbose -v --help -h" "$cur"
    else
        _kepr_compgen "user help --user --help" "$cur"
    fi
}

complete -F _kepr kepr
complete -F _kepr_daemon kepr-daemon
