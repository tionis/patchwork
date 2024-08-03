#!/bin/env bash
#--------------------------------------------
set -Eeuo pipefail
if [[ -n "${DEBUG:-}" ]]; then
	set -x
fi
trap stack_trace ERR
function stack_trace() {
	echo -e "\nThe command '$BASH_COMMAND' triggerd a stacktrace:\nStack Trace:"
	for ((i = 1; i < ${#FUNCNAME[@]}; i++)); do
		echo "    ($i) ${FUNCNAME[$i]:-(top level)} ${BASH_SOURCE[$i]:-(no file)}:${BASH_LINENO[$((i - 1))]}"
	done
}
error() { printf "\e[1;31m[ERROR]\e[0m %s\n" "${1:-error message missing}" && trap true ERR && exit 1; }
warning() { printf "\e[1;33m[WARNING]\e[0m %s\n" "$1" >&2; }
success() { printf "\e[1;32m[SUCCESS]\e[0m %s\n" "$1" >&2; }
info() { printf "\e[1;34m[INFO]\e[0m %s\n" "$1" >&2; }
green() { if [[ -t 0 ]]; then printf "\e[1;32m%s\e[0m" "$1"; else printf "%s" "$1"; fi; }
red() { if [[ -t 0 ]]; then printf "\e[1;31m%s\e[0m" "$1"; else printf "%s" "$1"; fi; }
blue() { if [[ -t 0 ]]; then printf "\e[1;34m%s\e[0m" "$1"; else printf "%s" "$1"; fi; }
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
export SCRIPT_DIR
#--------------------------------------------
declare -A patchwork_commands
declare -A patchwork_command_descriptions
patchwork:desc() {
	patchwork_commands["$1"]="$1"
	patchwork_command_descriptions["$1"]="$2"
}
declare -A patchwork_aliases
patchwork:alias() {
	patchwork_aliases["$1"]+="|$2"
	patchwork_commands["$2"]="$1"
}
patchwork:desc help "Show this help message"
patchwork:help() {
	case "${1:-list}" in
	*/)
		printf "Group Commands for %s:\n" "$(green "${1}")"
		for key in "${!patchwork_command_descriptions[@]}"; do
			if [[ "$key" == "${1}"* ]]; then
				local name_without_group="${key:${#1}}"
				if [[ (! "$name_without_group" == */*) ||
					"$name_without_group" =~ [a-zA-Z0-9]*/$ ]]; then
					if [[ -v ESCPAPED_NAME_aliases[$key] ]]; then
						printf "  %s: %s\n" \
							"$(green "$key${patchwork_aliases[$key]}")" \
							"${patchwork_command_descriptions[$key]}"
					else
						printf "  %s: %s\n" \
							"$(green "$key")" \
							"${patchwork_command_descriptions[$key]}"
					fi
				fi
			fi
		done
		;;
	list)
		echo "Usage: patchwork [command]"
		echo "Commands:"
		for key in "${!patchwork_command_descriptions[@]}"; do
			if [[ (! "$key" == */*) ||
				"$key" =~ [a-zA-Z0-9_.-]*/$ ]]; then
				if [[ -v patchwork_aliases[$key] ]]; then
					printf "  %s: %s\n" \
						"$(green "$key${patchwork_aliases[$key]}")" \
						"${patchwork_command_descriptions[$key]}"
				else
					printf "  %s: %s\n" \
						"$(green "$key")" \
						"${patchwork_command_descriptions[$key]}"
				fi
			fi
		done
		;;
	*)
		if [[ -v patchwork_command_descriptions[$1] ]]; then
			printf "Usage: patchwork %s\n" "$(green "$1")"
			if [[ -v patchwork_aliases[$1] ]]; then
				printf "Aliases: %s\n" "$(green "${patchwork_aliases[$1]//|/ }")"
			fi
			printf "%s\n" "${patchwork_command_descriptions[$1]}"
		else
			error "Unknown command: $1"
		fi
		;;
	esac
}

patchwork:get_uuid() {
	if command -v uuidgen &>/dev/null; then
		uuidgen
	else
		cat /proc/sys/kernel/random/uuid
	fi
}

######################################### Globals ##########################################
patchwork_server="${PATCHWORK_SERVER:-https://patch.tionis.dev}"
patchwork_server_req="$patchwork_server/req"

######################################### Commands ##########################################
patchwork:desc token "Create a new token"
patchwork:token() {
	declare allowedWritePaths allowedReadPaths validUntil key allowedReadPathsJSON allowedWritePathsJSON dataJSON
	allowedReadPaths=()
	allowedWritePaths=()
	validUntil="$(date --date='1 hour' +%s)"
	key=~/.ssh/id_ed25519
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--help)
			echo "Usage: $(basename "$0") token [options]"
			echo "Options:"
			echo "  -k, --key <key> The key to sign the token with, defaults to ~/.ssh/id_ed25519"
			echo "  -r, --read <path> Add a path to the allowed read paths, if not specified all paths are allowed"
			echo "  -w, --write <path> Add a path to the allowed write paths, if not specified all paths are allowed"
			echo "  -u, --until <time> The time until the token is valid, defaults to 1 hour from now"
			echo "  --no-read Disallow all read paths"
			echo "  --no-write Disallow all write paths"
			return 0
			;;
		--no-read)
			allowedReadPathsJSON="[]"
			;;
		--no-write)
			allowedWritePathsJSON="[]"
			;;
		-k | --key)
			shift
			key="$1"
			;;
		-r | --read)
			shift
			allowedReadPaths+=("$1")
			;;
		-w | --write)
			shift
			allowedWritePaths+=("$1")
			;;
		-u | --until)
			shift
			validUntil="$1"
			;;
		*)
			error "Unknown option: $1"
			;;
		esac
		shift
	done
	if [[ ! -f "$key" ]]; then
		error "Key file not found: $key"
	fi
	if [[ "${#allowedReadPaths[@]}" -eq 0 ]]; then
		allowedReadPaths+=("/")
	fi
	if [[ "${#allowedWritePaths[@]}" -eq 0 ]]; then
		allowedWritePaths+=("/")
	fi
	allowedReadPathsJSON="${allowedReadPathsJSON:-"$(printf '%s\n' "${allowedReadPaths[@]}" | jq -R . | jq -s .)"}"
	allowedWritePathsJSON="${allowedWritePathsJSON:-"$(printf '%s\n' "${allowedWritePaths[@]}" | jq -R . | jq -s .)"}"
	dataJSON="$(jq -cnS --argjson allowedReadPaths "$allowedReadPathsJSON" --argjson allowedWritePaths "$allowedWritePathsJSON" --argjson validUntil "$validUntil" '{allowedWritePaths: $allowedWritePaths, allowedReadPaths: $allowedReadPaths, validUntil: $validUntil}')"
	echo "$dataJSON" |
		ssh-keygen -Y sign -n patch.tionis.dev -f "$key" |
		jq -cRn '{signature: ([inputs] | join("\n")), data: $data}' --arg data "$dataJSON" |
		gzip |
		base64 --wrap=0
}

patchwork:desc send "Send data via the patchwork server"
patchwork:send() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--help)
			echo "Usage: $(basename "$0") send [options] <filename>"
			echo "Options:"
			echo "  -i, --id <id> The id of the data to send, if not specified a random UUID will be generated"
			return 0
			;;
		-i | --id)
			shift
			id="$1"
			;;
		*)
			filename="$1"
			;;
		esac
		shift
	done
	if [[ -z "${filename:-}" ]]; then
		error "No filename specified"
	fi
	id="${id:-$(patchwork:get_uuid)}"
	info "Sending data to $patchwork_server_req/$id"
	if [[ "$filename" == "-" ]]; then
		curl -X POST --data-binary @- "$patchwork_server_req/$id"
	else
		curl -X POST --data-binary "@$filename" "$patchwork_server_req/$id"
	fi

}

######################################### Main ##############################################
patchwork:main() {
	if [[ "$(basename "$0")" = "patchwork" ]]; then
		command="${1:-help}"
	else
		command="$(basename "$0")"
	fi
	shift || true
	if [[ "$command" == */ ]]; then
		"patchwork:help" "$command" "$@"
	elif [[ -v patchwork_commands[$command] ]]; then
		"patchwork:${patchwork_commands[$command]}" "$@"
	else
		error "Unknown command: $command"
	fi
}
if [[ $- != *i* ]]; then
	patchwork:main "$@"
fi