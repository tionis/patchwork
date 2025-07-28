#!/usr/bin/env bash
#--------------------------------------------
set -Eeuo pipefail
if [[ -n "${DEBUG:-}" ]]; then
	set -x
fi
trap stack_trace ERR
function stack_trace() {
	echo -e "\nThe command '$BASH_COMMAND' triggered a stacktrace:\nStack Trace:"
	for ((i = 1; i < ${#FUNCNAME[@]}; i++)); do
		echo "    ($i) ${FUNCNAME[$i]:-(top level)} ${BASH_SOURCE[$i]:-(no file)}:${BASH_LINENO[$((i - 1))]}"
	done
}
error() { printf "\e[1;31m[ERROR]\e[0m %s\n" "${1:-error message missing}" && trap true ERR && return 1; }
warning() { printf "\e[1;33m[WARNING]\e[0m %s\n" "$1" >&2; }
success() { printf "\e[1;32m[SUCCESS]\e[0m %s\n" "$1" >&2; }
info() { printf "\e[1;34m[INFO]\e[0m %s\n" "$1" >&2; }
green() { if [[ -t 0 ]]; then printf "\e[1;32m%s\e[0m" "$1"; else printf "%s" "$1"; fi; }
red() { if [[ -t 0 ]]; then printf "\e[1;31m%s\e[0m" "$1"; else printf "%s" "$1"; fi; }
blue() { if [[ -t 0 ]]; then printf "\e[1;34m%s\e[0m" "$1"; else printf "%s" "$1"; fi; }
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
export SCRIPT_DIR
#--------------------------------------------
declare -A patchwork__commands
declare -A patchwork__command_descriptions
patchwork::desc() {
	patchwork__commands["$1"]="$1"
	patchwork__command_descriptions["$1"]="$2"
}
declare -A patchwork__aliases
patchwork::alias() {
	patchwork__aliases["$1"]+="|$2"
	patchwork__commands["$2"]="$1"
}
patchwork::desc help "Show this help message"
patchwork::help() {
	case "${1:-list}" in
	*/)
		printf "Group Commands for %s:\n" "$(green "${1}")"
		for key in "${!patchwork__command_descriptions[@]}"; do
			if [[ "$key" == "${1}"?* ]]; then
				local name_without_group="${key:${#1}}"
				if [[ (! "$name_without_group" == */*) ||
					"$name_without_group" =~ ^[a-zA-Z0-9]+/$ ]]; then
					if [[ -v patchwork__aliases[$key] ]]; then
						printf "  %s: %s\n" \
							"$(green "$key${patchwork__aliases[$key]}")" \
							"${patchwork__command_descriptions[$key]}"
					else
						printf "  %s: %s\n" \
							"$(green "$key")" \
							"${patchwork__command_descriptions[$key]}"
					fi
				fi
			fi
		done
		;;
	list)
		echo "Usage: patchwork [command]"
		echo "Commands:"
		for key in "${!patchwork__command_descriptions[@]}"; do
			if [[ (! "$key" == */*) ||
				"$key" =~ ^[a-zA-Z0-9_.-]+/$ ]]; then
				if [[ -v patchwork__aliases[$key] ]]; then
					printf "  %s: %s\n" \
						"$(green "$key${patchwork__aliases[$key]}")" \
						"${patchwork__command_descriptions[$key]}"
				else
					printf "  %s: %s\n" \
						"$(green "$key")" \
						"${patchwork__command_descriptions[$key]}"
				fi
			fi
		done
		;;
	*)
		if [[ -v patchwork__command_descriptions[$1] ]]; then
			printf "Usage: patchwork %s\n" "$(green "$1")"
			if [[ -v patchwork__aliases[$1] ]]; then
				printf "Aliases: %s\n" "$(green "${patchwork__aliases[$1]//|/ }")"
			fi
			printf "%s\n" "${patchwork__command_descriptions[$1]}"
		else
			error "Unknown command: $1"
		fi
		;;
	esac
}

patchwork() {
	local base_zero
	base_zero="$(basename "$0")"
	if [[ "$base_zero" = ".main" || "$base_zero" = "patchwork" || "$base_zero" = "patchwork.sh" ]]; then
		command="${1:-help}"
		shift || true
	else
		command="$base_zero"
	fi
	if [[ "$command" == */ ]]; then
		"patchwork::help" "$command" "$@"
	elif [[ -v patchwork__commands[$command] ]]; then
		"patchwork::${patchwork__commands[$command]}" "$@"
	else
		error "Unknown command: $command"
	fi
}

######################################### Globals ##########################################
patchwork__server="${PATCHWORK_SERVER:-https://patch.tionis.dev}"

# Generate a random UUID-like string
patchwork::get_uuid() {
	if command -v uuidgen >/dev/null 2>&1; then
		uuidgen
	else
		# Fallback: generate a random hex string
		printf "%08x-%04x-%04x-%04x-%012x\n" \
			$((RANDOM * 65536 + RANDOM)) \
			$((RANDOM)) \
			$((RANDOM)) \
			$((RANDOM)) \
			$((RANDOM * 65536 + RANDOM)) \
			$((RANDOM * 65536 + RANDOM))
	fi
}

######################################### Commands ##########################################
patchwork::desc send "Send data to a channel"
patchwork::alias send pub
patchwork::alias send publish
patchwork::send() {
	local channel="" data="" mode="queue" namespace="p"
	local secret="" body_param="" token=""
	
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--help)
			echo "Usage: $(basename "$0") send [options] <channel> [data]"
			echo ""
			echo "Send data to a patchwork channel."
			echo ""
			echo "Arguments:"
			echo "  channel           The channel name to send to"
			echo "  data              Data to send (or read from stdin if '-' or not provided)"
			echo ""
			echo "Options:"
			echo "  -m, --mode <mode>     Mode: queue (default) or pubsub"
			echo "  -n, --namespace <ns>  Namespace: p (default), h (forward hooks), r (reverse hooks), u (user)"
			echo "  -s, --secret <secret> Secret for authenticated namespaces (h for sending, r for receiving)"
			echo "  -t, --token <token>   Token for user namespaces (u)"
			echo "  -g, --get             Use GET request with body parameter instead of POST"
			echo "  -f, --file <file>     Read data from file"
			echo ""
			echo "Examples:"
			echo "  patchwork send mychannel 'hello world'"
			echo "  echo 'hello' | patchwork send mychannel"
			echo "  patchwork send -m pubsub mychannel 'broadcast message'"
			echo "  patchwork send -n h -s mysecret webhook-data 'notification'"
			echo "  patchwork send -n u -t mytoken alice/projects/logs 'deploy completed'"
			return 0
			;;
		-m | --mode)
			shift
			mode="$1"
			;;
		-n | --namespace)
			shift
			namespace="$1"
			;;
		-s | --secret)
			shift
			secret="$1"
			;;
		-t | --token)
			shift
			token="$1"
			;;
		-g | --get)
			body_param="true"
			;;
		-f | --file)
			shift
			if [[ "$1" == "-" ]]; then
				data="$(cat)"
			else
				data="$(cat "$1")"
			fi
			;;
		-*)
			error "Unknown option: $1"
			;;
		*)
			if [[ -z "$channel" ]]; then
				channel="$1"
			elif [[ -z "$data" ]]; then
				data="$1"
			else
				error "Too many arguments"
			fi
			;;
		esac
		shift
	done
	
	if [[ -z "$channel" ]]; then
		error "Channel name required"
	fi
	
	# Read from stdin if no data provided
	if [[ -z "$data" ]]; then
		data="$(cat)"
	fi
	
	# Build URL
	local url="$patchwork__server/$namespace/$channel"
	local params=""
	
	# Add mode parameter if not default
	if [[ "$mode" != "queue" ]]; then
		params="${params:+$params&}$mode=true"
	fi
	
	# Add secret parameter for authenticated namespaces
	# For 'h' namespace, secret is required for sending
	if [[ -n "$secret" && ("$namespace" == "h" || "$namespace" == "r") ]]; then
		params="${params:+$params&}secret=$secret"
	fi
	
	# Add token parameter for user namespaces
	if [[ -n "$token" && "$namespace" == "u" ]]; then
		params="${params:+$params&}token=$token"
	fi
	
	# Handle GET request with body parameter
	if [[ -n "$body_param" ]]; then
		local encoded_data
		encoded_data="$(printf '%s' "$data" | jq -sRr @uri)"
		params="${params:+$params&}body=$encoded_data"
		url="$url${params:+?$params}"
		
		info "Sending data via GET to: $url"
		curl -s "$url"
	else
		url="$url${params:+?$params}"
		
		info "Sending data to: $url"
		printf '%s' "$data" | curl -s -X POST --data-binary @- "$url"
	fi
}

patchwork::desc receive "Receive data from a channel"
patchwork::alias receive sub
patchwork::alias receive subscribe
patchwork::alias receive get
patchwork::receive() {
	local channel="" namespace="p" secret="" timeout="" token=""
	
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--help)
			echo "Usage: $(basename "$0") receive [options] <channel>"
			echo ""
			echo "Receive data from a patchwork channel."
			echo ""
			echo "Arguments:"
			echo "  channel           The channel name to receive from"
			echo ""
			echo "Options:"
			echo "  -n, --namespace <ns>  Namespace: p (default), h (forward hooks), r (reverse hooks), u (user)"
			echo "  -s, --secret <secret> Secret for authenticated namespaces (r for reading)"
			echo "  -t, --token <token>   Token for user namespaces (u)"
			echo "  -T, --timeout <sec>   Timeout in seconds (default: no timeout)"
			echo ""
			echo "Examples:"
			echo "  patchwork receive mychannel"
			echo "  patchwork receive -n h webhook-data"
			echo "  patchwork receive -n r -s mysecret collected-data"
			echo "  patchwork receive -n u -t mytoken alice/projects/status"
			return 0
			;;
		-n | --namespace)
			shift
			namespace="$1"
			;;
		-s | --secret)
			shift
			secret="$1"
			;;
		-t | --token)
			shift
			token="$1"
			;;
		-T | --timeout)
			shift
			timeout="$1"
			;;
		-*)
			error "Unknown option: $1"
			;;
		*)
			if [[ -z "$channel" ]]; then
				channel="$1"
			else
				error "Too many arguments"
			fi
			;;
		esac
		shift
	done
	
	if [[ -z "$channel" ]]; then
		error "Channel name required"
	fi
	
	# Build URL
	local url="$patchwork__server/$namespace/$channel"
	local params=""
	
	# Add secret parameter for authenticated namespaces
	# For 'r' namespace, secret is required for reading
	if [[ -n "$secret" && "$namespace" == "r" ]]; then
		params="${params:+$params&}secret=$secret"
	fi
	
	# Add token parameter for user namespaces
	if [[ -n "$token" && "$namespace" == "u" ]]; then
		params="${params:+$params&}token=$token"
	fi
	
	url="$url${params:+?$params}"
	
	info "Receiving data from: $url"
	
	if [[ -n "$timeout" ]]; then
		curl -s --max-time "$timeout" "$url"
	else
		curl -s "$url"
	fi
}

patchwork::desc listen "Listen for notifications with a magic prefix"
patchwork::listen() {
	local channel="" namespace="p" secret="" magic="notify" sleep_time=1 token=""
	
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--help)
			echo "Usage: $(basename "$0") listen [options] <channel>"
			echo ""
			echo "Listen for notifications on a channel with a magic prefix."
			echo "Useful for desktop notifications and webhooks."
			echo ""
			echo "Arguments:"
			echo "  channel           The channel name to listen to"
			echo ""
			echo "Options:"
			echo "  -n, --namespace <ns>  Namespace: p (default), h (forward hooks), r (reverse hooks), u (user)"
			echo "  -s, --secret <secret> Secret for authenticated namespaces (r for reading)"
			echo "  -t, --token <token>   Token for user namespaces (u)"
			echo "  -m, --magic <prefix>  Magic prefix to look for (default: 'notify')"
			echo "  --sleep <seconds>     Sleep time between failed requests (default: 1)"
			echo ""
			echo "Examples:"
			echo "  patchwork listen notifications"
			echo "  patchwork listen -m 'alert' mychannel"
			echo "  patchwork listen -n u -t mytoken alice/alerts"
			return 0
			;;
		-n | --namespace)
			shift
			namespace="$1"
			;;
		-s | --secret)
			shift
			secret="$1"
			;;
		-t | --token)
			shift
			token="$1"
			;;
		-m | --magic)
			shift
			magic="$1"
			;;
		--sleep)
			shift
			sleep_time="$1"
			;;
		-*)
			error "Unknown option: $1"
			;;
		*)
			if [[ -z "$channel" ]]; then
				channel="$1"
			else
				error "Too many arguments"
			fi
			;;
		esac
		shift
	done
	
	if [[ -z "$channel" ]]; then
		error "Channel name required"
	fi
	
	# Build URL
	local url="$patchwork__server/$namespace/$channel"
	local params=""
	
	# Add secret parameter for authenticated namespaces
	if [[ -n "$secret" && "$namespace" == "r" ]]; then
		params="${params:+$params&}secret=$secret"
	fi
	
	# Add token parameter for user namespaces
	if [[ -n "$token" && "$namespace" == "u" ]]; then
		params="${params:+$params&}token=$token"
	fi
	
	url="$url${params:+?$params}"
	
	info "Listening for '$magic' prefixed messages on: $url"
	
	while true; do
		local response
		response="$(curl -s "$url" || echo "")"
		
		if [[ "$response" =~ ^$magic ]]; then
			local message="${response#$magic}"
			echo "$message"
			# Optionally trigger desktop notification if notify-send is available
			if command -v notify-send >/dev/null 2>&1; then
				notify-send "$message" 2>/dev/null || true
			fi
		else
			sleep "$sleep_time"
		fi
	done
}

patchwork::desc share "Share a file via patchwork"
patchwork::share() {
	local file="" channel="" namespace="p"
	
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--help)
			echo "Usage: $(basename "$0") share [options] <file> [channel]"
			echo ""
			echo "Share a file via patchwork. If no channel is specified, uses the filename."
			echo ""
			echo "Arguments:"
			echo "  file              File to share"
			echo "  channel           Channel name (defaults to filename)"
			echo ""
			echo "Options:"
			echo "  -n, --namespace <ns>  Namespace: p (default), h (forward hooks), r (reverse hooks)"
			echo ""
			echo "Examples:"
			echo "  patchwork share document.pdf"
			echo "  patchwork share image.jpg my-image"
			return 0
			;;
		-n | --namespace)
			shift
			namespace="$1"
			;;
		-*)
			error "Unknown option: $1"
			;;
		*)
			if [[ -z "$file" ]]; then
				file="$1"
			elif [[ -z "$channel" ]]; then
				channel="$1"
			else
				error "Too many arguments"
			fi
			;;
		esac
		shift
	done
	
	if [[ -z "$file" ]]; then
		error "File path required"
	fi
	
	if [[ ! -f "$file" ]]; then
		error "File not found: $file"
	fi
	
	# Use filename as channel if not specified
	if [[ -z "$channel" ]]; then
		channel="$(basename "$file")"
	fi
	
	local url="$patchwork__server/$namespace/$channel"
	
	info "Sharing file '$file' as '$channel' at: $url"
	success "Others can download with: curl '$url' > '$channel'"
	
	curl -s -X POST --data-binary "@$file" "$url"
}

patchwork::desc download "Download a file via patchwork"
patchwork::download() {
	local channel="" namespace="p" output=""
	
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--help)
			echo "Usage: $(basename "$0") download [options] <channel> [output]"
			echo ""
			echo "Download a file via patchwork."
			echo ""
			echo "Arguments:"
			echo "  channel           Channel name to download from"
			echo "  output            Output filename (defaults to channel name)"
			echo ""
			echo "Options:"
			echo "  -n, --namespace <ns>  Namespace: p (default), h (forward hooks), r (reverse hooks)"
			echo ""
			echo "Examples:"
			echo "  patchwork download document.pdf"
			echo "  patchwork download my-image downloaded-image.jpg"
			return 0
			;;
		-n | --namespace)
			shift
			namespace="$1"
			;;
		-*)
			error "Unknown option: $1"
			;;
		*)
			if [[ -z "$channel" ]]; then
				channel="$1"
			elif [[ -z "$output" ]]; then
				output="$1"
			else
				error "Too many arguments"
			fi
			;;
		esac
		shift
	done
	
	if [[ -z "$channel" ]]; then
		error "Channel name required"
	fi
	
	# Use channel name as output filename if not specified
	if [[ -z "$output" ]]; then
		output="$channel"
	fi
	
	local url="$patchwork__server/$namespace/$channel"
	
	info "Downloading from: $url"
	info "Saving as: $output"
	
	curl -s "$url" > "$output"
	success "Downloaded '$channel' to '$output'"
}

# Run main if not sourced
if [[ "$0" == "${BASH_SOURCE[0]}" ]]; then
	patchwork "$@"
fi
