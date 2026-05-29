#!/bin/sh
set -u

PROJECT_NAME=moss
OWNER=c3b2a7
REPO=moss
GITHUB_REPO_URL=https://github.com/${OWNER}/${REPO}
GITHUB_API_URL=https://api.github.com/repos/${OWNER}/${REPO}
GITHUB_DOWNLOAD_PREFIX=${GITHUB_REPO_URL}/releases/download

is_command() (
  command -v "$1" >/dev/null 2>&1
)

echo_stderr() (
  echo "$@" 1>&2
)

_logp=2
log_set_priority() {
  _logp="$1"
}

log_priority() (
  [ "$1" -le "$_logp" ]
)

init_colors() {
  RED=''
  BLUE=''
  PURPLE=''
  BOLD=''
  RESET=''

  if test -t 1 && is_command tput; then
    ncolors=$(tput colors 2>/dev/null || echo 0)
    if test -n "$ncolors" && test "$ncolors" -ge 8; then
      RED='\033[0;31m'
      BLUE='\033[0;34m'
      PURPLE='\033[0;35m'
      BOLD='\033[1m'
      RESET='\033[0m'
    fi
  fi
}

init_colors

log_tag() (
  case $1 in
  0) echo "${RED}${BOLD}[error]${RESET}" ;;
  1) echo "${RED}[warn]${RESET}" ;;
  2) echo "[info]" ;;
  3) echo "${BLUE}[debug]${RESET}" ;;
  4) echo "${PURPLE}[trace]${RESET}" ;;
  *) echo "[$1]" ;;
  esac
)

log_trace_priority=4
log_trace() (
  priority=$log_trace_priority
  log_priority "$priority" || return 0
  echo_stderr "$(log_tag "$priority")" "$@" "${RESET}"
)

log_debug_priority=3
log_debug() (
  priority=$log_debug_priority
  log_priority "$priority" || return 0
  echo_stderr "$(log_tag "$priority")" "$@" "${RESET}"
)

log_info_priority=2
log_info() (
  priority=$log_info_priority
  log_priority "$priority" || return 0
  echo_stderr "$(log_tag "$priority")" "$@" "${RESET}"
)

log_warn_priority=1
log_warn() (
  priority=$log_warn_priority
  log_priority "$priority" || return 0
  echo_stderr "$(log_tag "$priority")" "$@" "${RESET}"
)

log_err_priority=0
log_err() (
  priority=$log_err_priority
  log_priority "$priority" || return 0
  echo_stderr "$(log_tag "$priority")" "$@" "${RESET}"
)

http_download_curl() (
  local_file=$1
  source_url=$2

  log_trace "http_download_curl(local_file=${local_file}, source_url=${source_url})"
  curl -fL -s -o "$local_file" "$source_url"
)

http_download_wget() (
  local_file=$1
  source_url=$2

  log_trace "http_download_wget(local_file=${local_file}, source_url=${source_url})"
  wget -q -O "$local_file" "$source_url"
)

http_download() (
  if is_command curl; then
    http_download_curl "$@"
    return
  elif is_command wget; then
    http_download_wget "$@"
    return
  fi

  log_err "unable to find curl or wget"
  return 1
)

http_copy() (
  tmp=$(mktemp)
  if ! http_download "$tmp" "$1"; then
    rm -f "$tmp"
    return 1
  fi
  body=$(cat "$tmp")
  rm -f "$tmp"
  echo "$body"
)

hash_sha256() (
  target=$1

  if is_command gsha256sum; then
    hash=$(gsha256sum "$target") || return 1
    echo "$hash" | cut -d ' ' -f 1
  elif is_command sha256sum; then
    hash=$(sha256sum "$target") || return 1
    echo "$hash" | cut -d ' ' -f 1
  elif is_command shasum; then
    hash=$(shasum -a 256 "$target" 2>/dev/null) || return 1
    echo "$hash" | cut -d ' ' -f 1
  elif is_command openssl; then
    hash=$(openssl dgst -sha256 "$target") || return 1
    echo "$hash" | cut -d '=' -f 2 | xargs
  else
    log_err "unable to find a command to compute sha256"
    return 1
  fi
)

verify_sha256() (
  target=$1
  checksums=$2
  target_basename=${target##*/}

  want=$(grep "$target_basename" "$checksums" 2>/dev/null | tr '\t' ' ' | cut -d ' ' -f 1 | head -n 1)
  if [ -z "$want" ]; then
    log_err "unable to find checksum for ${target_basename}"
    return 1
  fi

  got=$(hash_sha256 "$target") || return 1
  if [ "$want" != "$got" ]; then
    log_err "checksum mismatch for ${target_basename}: expected ${want}, got ${got}"
    return 1
  fi
)

latest_release_tag() (
  json=$(http_copy "${GITHUB_API_URL}/releases/latest") || return 1
  tag=$(echo "$json" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 | cut -d '"' -f 4)
  test -n "$tag" || return 1
  echo "$tag"
)

resolve_tag() (
  tag=$1

  if [ -n "$tag" ]; then
    echo "$tag"
    return 0
  fi

  latest_release_tag
)

uname_target() (
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)

  case "$os" in
  darwin) ;;
  *)
    log_err "prebuilt releases are only available for macOS; install Rust and re-run this script to use cargo install"
    return 1
    ;;
  esac

  case "$arch" in
  arm64 | aarch64) arch=aarch64 ;;
  x86_64 | amd64) arch=x86_64 ;;
  *)
    log_err "unsupported macOS architecture: ${arch}"
    return 1
    ;;
  esac

  echo "${arch}-apple-darwin"
)

install_with_cargo() (
  install_dir=$1
  tag=$2
  cargo_install_dir=${install_dir%/}

  case "$cargo_install_dir" in
  bin) cargo_root=. ;;
  */bin) cargo_root=${cargo_install_dir%/bin} ;;
  *)
    log_err "cargo install writes to ROOT/bin; installation directory must end in /bin"
    return 1
    ;;
  esac

  log_info "cargo found; installing ${PROJECT_NAME} from ${GITHUB_REPO_URL}"
  log_info "using release tag ${tag}"
  cargo install --force --locked --git "$GITHUB_REPO_URL" --tag "$tag" --root "$cargo_root" "$PROJECT_NAME"
)

install_release() (
  install_dir=$1
  tag=$2
  target=$(uname_target) || return 1
  asset="${PROJECT_NAME}-${target}.tar.gz"
  download_url="${GITHUB_DOWNLOAD_PREFIX}/${tag}"
  tmp_dir=$(mktemp -d)

  log_info "cargo not found; downloading ${asset} from GitHub Releases"
  log_debug "using temporary directory ${tmp_dir}"

  if ! http_download "${tmp_dir}/SHA256SUMS" "${download_url}/SHA256SUMS"; then
    rm -rf "$tmp_dir"
    log_err "failed to download SHA256SUMS for ${tag}"
    return 1
  fi

  if ! http_download "${tmp_dir}/${asset}" "${download_url}/${asset}"; then
    rm -rf "$tmp_dir"
    log_err "failed to download ${asset}"
    return 1
  fi

  if ! verify_sha256 "${tmp_dir}/${asset}" "${tmp_dir}/SHA256SUMS"; then
    rm -rf "$tmp_dir"
    return 1
  fi
  log_info "checksum verification succeeded"

  if ! tar -xzf "${tmp_dir}/${asset}" -C "$tmp_dir"; then
    rm -rf "$tmp_dir"
    log_err "failed to unpack ${asset}"
    return 1
  fi

  install -d "$install_dir"
  install "${tmp_dir}/${PROJECT_NAME}" "${install_dir}/${PROJECT_NAME}"
  rm -rf "$tmp_dir"
)

usage() {
  cat <<EOF
Download and install ${PROJECT_NAME}.

Usage: $0 [-b DIR] [-d] [TAG]
  -b DIR  installation directory (default: \$HOME/.local/bin)
  -d      turn on debug logging; use -dd for trace logging
  TAG     release tag to install, for example v0.1.0

The installer uses cargo install when cargo is available. Without cargo, it
downloads the matching macOS release archive and verifies it with SHA256SUMS.
If TAG is omitted, the latest GitHub Release tag is used.
EOF
}

main() (
  install_dir=${INSTALL_DIR:-"${HOME}/.local/bin"}

  while getopts "b:dh?" arg; do
    case "$arg" in
    b) install_dir="$OPTARG" ;;
    d)
      if [ "$_logp" = "$log_info_priority" ]; then
        log_set_priority "$log_debug_priority"
      else
        log_set_priority "$log_trace_priority"
      fi
      ;;
    h | \?)
      usage
      exit 0
      ;;
    esac
  done
  shift $((OPTIND - 1))

  set +u
  requested_tag=$1
  set -u

  if [ -z "$requested_tag" ]; then
    log_info "checking GitHub for the latest release"
  fi

  if ! tag=$(resolve_tag "$requested_tag"); then
    log_err "unable to determine release tag"
    log_err "choose a tag from ${GITHUB_REPO_URL}/releases and pass it to this script"
    return 1
  fi

  log_info "installing ${PROJECT_NAME} ${tag} to ${install_dir}"

  if is_command cargo; then
    install_with_cargo "$install_dir" "$tag"
  else
    install_release "$install_dir" "$tag"
  fi
  status=$?

  if [ "$status" -ne 0 ]; then
    log_err "failed to install ${PROJECT_NAME}"
    return "$status"
  fi

  log_info "installed ${install_dir}/${PROJECT_NAME}"
)

main "$@"
