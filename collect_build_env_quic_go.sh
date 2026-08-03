#!/usr/bin/env bash
# Read-only environment collector for the quic-go experiment binaries.
# It does not install, download, build, initialize submodules, or write files.

set -u

section() {
  printf '\n===== %s =====\n' "$1"
}

not_found() {
  printf '%s: NOT FOUND\n' "$1"
}

show_command() {
  local label=$1
  shift
  local command_name=$1
  if ! command -v "$command_name" >/dev/null 2>&1; then
    not_found "$label"
    return 0
  fi
  printf '%s:\n' "$label"
  "$@" 2>&1 || printf '%s: COMMAND FAILED (exit=%s)\n' "$label" "$?"
}

show_first_line_version() {
  local command_name=$1
  shift
  if ! command -v "$command_name" >/dev/null 2>&1; then
    not_found "$command_name"
    return 0
  fi
  local output
  output=$("$command_name" "$@" 2>&1)
  local command_rc=$?
  if [ "$command_rc" -ne 0 ]; then
    printf '%s: COMMAND FAILED (exit=%s): %s\n' "$command_name" "$command_rc" "$output"
    return 0
  fi
  printf '%s: %s\n' "$command_name" "${output%%$'\n'*}"
}

resolve_repo_root() {
  local candidate
  candidate=$(GIT_OPTIONAL_LOCKS=0 git -C "$PWD" rev-parse --show-toplevel 2>/dev/null) && {
    printf '%s\n' "$candidate"
    return 0
  }
  if [ -f "$PWD/go.mod" ]; then
    candidate=$(CDPATH= cd -- "$PWD" 2>/dev/null && pwd -P) && {
      printf '%s\n' "$candidate"
      return 0
    }
  fi
  if command -v go >/dev/null 2>&1; then
    candidate=$(GOTOOLCHAIN=local go env GOMOD 2>/dev/null)
    if [ -n "$candidate" ] && [ "$candidate" != "/dev/null" ] && [ -f "$candidate" ]; then
      candidate=$(CDPATH= cd -- "$(dirname -- "$candidate")" 2>/dev/null && pwd -P) && {
        printf '%s\n' "$candidate"
        return 0
      }
    fi
  fi
  candidate=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)
  if [ -f "$candidate/go.mod" ]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  candidate=$(CDPATH= cd -- "$PWD" 2>/dev/null && pwd -P)
  printf '%s\n' "${candidate:-$PWD}"
}

inspect_binary() {
  local binary_path=$1
  printf '\nBINARY: %s\n' "$binary_path"
  if [ ! -f "$binary_path" ]; then
    printf 'exists: NO\n'
    return 0
  fi
  printf 'exists: YES\n'
  if [ -x "$binary_path" ]; then
    printf 'executable_bit: YES\n'
  else
    printf 'executable_bit: NO\n'
  fi
  if command -v file >/dev/null 2>&1; then
    file "$binary_path" 2>&1 || printf 'file: COMMAND FAILED (exit=%s)\n' "$?"
  else
    not_found "file"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$binary_path" 2>&1 || printf 'sha256sum: COMMAND FAILED (exit=%s)\n' "$?"
  else
    not_found "sha256sum"
  fi
  if command -v ldd >/dev/null 2>&1; then
    printf 'ldd:\n'
    ldd "$binary_path" 2>&1 || printf 'ldd: nonzero exit=%s (normal for a static Go binary)\n' "$?"
  else
    not_found "ldd"
  fi
  if command -v go >/dev/null 2>&1; then
    printf 'go version -m:\n'
    GOTOOLCHAIN=local go version -m "$binary_path" 2>&1 || printf 'go version -m: COMMAND FAILED (exit=%s)\n' "$?"
  else
    not_found "go version -m"
  fi
}

REPO_ROOT=$(resolve_repo_root)
export GIT_OPTIONAL_LOCKS=0

printf 'QUIC_GO_BUILD_ENV_REPORT_V1\n'
printf 'generated_utc: '
if command -v date >/dev/null 2>&1; then
  date -u '+%Y-%m-%dT%H:%M:%SZ' 2>&1 || printf 'COMMAND FAILED\n'
else
  printf 'NOT FOUND\n'
fi

section "A. BASIC ENVIRONMENT"
show_command "uname" uname -a
show_command "architecture" uname -m
if command -v nproc >/dev/null 2>&1; then
  printf 'cpu_online_count: %s\n' "$(nproc 2>&1)"
elif command -v getconf >/dev/null 2>&1; then
  printf 'cpu_online_count: %s\n' "$(getconf _NPROCESSORS_ONLN 2>&1)"
else
  not_found "cpu_online_count (nproc/getconf)"
fi
if [ -r /proc/cpuinfo ]; then
  cpu_model=$(awk -F: '/model name/{sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)
  printf 'cpu_model: %s\n' "${cpu_model:-NOT FOUND}"
else
  printf 'cpu_model: NOT FOUND\n'
fi
if command -v free >/dev/null 2>&1; then
  show_command "memory" free -h
elif [ -r /proc/meminfo ]; then
  printf 'memory:\n'
  awk '/^(MemTotal|MemAvailable|SwapTotal):/{print}' /proc/meminfo
else
  not_found "memory (free or /proc/meminfo)"
fi
show_command "disk_space_for_repo" df -hP "$REPO_ROOT"
if command -v id >/dev/null 2>&1; then
  show_command "current_user" id
else
  not_found "id"
fi
printf 'USER_env: %s\n' "${USER:-NOT FOUND}"
printf 'SHELL_env: %s\n' "${SHELL:-NOT FOUND}"
printf 'running_bash: %s\n' "${BASH_VERSION:-NOT FOUND}"
if command -v sudo >/dev/null 2>&1; then
  printf 'sudo_command: PRESENT at %s (not executed)\n' "$(command -v sudo)"
else
  printf 'sudo_command: NOT FOUND\n'
fi
if [ -r /etc/os-release ]; then
  printf 'os_release:\n'
  sed -n 's/^\(NAME\|VERSION\|VERSION_ID\|ID\)=/\1=/p' /etc/os-release
else
  printf 'os_release: NOT FOUND\n'
fi

section "B. REQUIRED BUILD TOOLS"
show_first_line_version bash --version
show_first_line_version git --version
if command -v go >/dev/null 2>&1; then
  printf 'go_path: %s\n' "$(command -v go)"
  GOTOOLCHAIN=local go version 2>&1 || printf 'go version: COMMAND FAILED (exit=%s)\n' "$?"
  printf 'go_env (forced GOTOOLCHAIN=local; no toolchain download):\n'
  GOTOOLCHAIN=local go env -json \
    GOVERSION GOOS GOARCH GOHOSTOS GOHOSTARCH CGO_ENABLED CC CXX \
    GOROOT GOPATH GOMOD GOWORK GOENV GOFLAGS GOTOOLCHAIN GOPROXY GOSUMDB \
    GOMODCACHE GOCACHE 2>&1 || printf 'go env: COMMAND FAILED (exit=%s)\n' "$?"
else
  not_found "go"
fi

printf '\nC compiler status (only conditionally relevant when CGO_ENABLED=1):\n'
show_first_line_version gcc --version
show_first_line_version g++ --version
show_first_line_version clang --version
show_first_line_version clang++ --version

printf '\nNot required by the two target packages based on this repository:\n'
printf 'cmake/ninja/make/pkg-config/rust/cargo/python: NOT PROBED (no matching target build configuration)\n'

section "C. PROJECT BUILD CONFIGURATION AND DEPENDENCIES"
printf 'repo_root: %s\n' "$REPO_ROOT"
for config_path in go.mod go.sum go.work .gitmodules CMakeLists.txt Cargo.toml Makefile; do
  if [ -e "$REPO_ROOT/$config_path" ]; then
    printf '%s: PRESENT\n' "$config_path"
  else
    printf '%s: NOT FOUND\n' "$config_path"
  fi
done
printf 'nested_build_configs (max depth 3):\n'
if command -v find >/dev/null 2>&1; then
  nested_configs=$(find "$REPO_ROOT" -maxdepth 3 -type f \( \
    -name 'go.mod' -o -name 'go.work' -o -name 'CMakeLists.txt' -o \
    -name 'Cargo.toml' -o -name 'Makefile' -o -name '*.mk' \
  \) -print 2>/dev/null)
  if [ -n "$nested_configs" ]; then
    printf '%s\n' "$nested_configs"
  else
    printf 'NOT FOUND\n'
  fi
else
  not_found "find"
fi

if [ -r "$REPO_ROOT/go.mod" ]; then
  printf '\ngo.mod identity and toolchain requirements:\n'
  awk '/^(module|go|toolchain|replace)[[:space:]]/{print}' "$REPO_ROOT/go.mod"
  printf 'go.mod direct/indirect module entries:\n'
  awk '$1 ~ /^[[:alnum:]._-]+\/[[:alnum:]_.\/-]+$/ && $2 ~ /^v[0-9]/{print $1, $2}' "$REPO_ROOT/go.mod"
else
  printf 'go.mod details: NOT FOUND\n'
fi
if [ -f "$REPO_ROOT/go.sum" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    printf 'go.sum sha256: '
    sha256sum "$REPO_ROOT/go.sum" 2>&1
  else
    not_found "sha256sum for go.sum"
  fi
  if command -v wc >/dev/null 2>&1; then
    printf 'go.sum lines: '
    wc -l < "$REPO_ROOT/go.sum"
  else
    not_found "wc for go.sum"
  fi
fi

if [ -d "$REPO_ROOT/vendor" ]; then
  printf 'vendor_directory: PRESENT\n'
  if [ -f "$REPO_ROOT/vendor/modules.txt" ]; then
    printf 'vendor/modules.txt: PRESENT\n'
  else
    printf 'vendor/modules.txt: NOT FOUND\n'
  fi
else
  printf 'vendor_directory: NOT FOUND\n'
fi

printf 'local_output_directories:\n'
for local_dir in bin build out dist; do
  if [ -d "$REPO_ROOT/$local_dir" ]; then
    printf '%s: PRESENT at %s\n' "$local_dir" "$REPO_ROOT/$local_dir"
  else
    printf '%s: NOT FOUND\n' "$local_dir"
  fi
done

printf 'cgo_source_imports_under_targets:\n'
if command -v grep >/dev/null 2>&1; then
  cgo_hits=$(grep -R -n --include='*.go' 'import "C"' \
    "$REPO_ROOT/example" "$REPO_ROOT/http3" "$REPO_ROOT/internal" 2>/dev/null)
  if [ -n "$cgo_hits" ]; then
    printf '%s\n' "$cgo_hits"
  else
    printf 'NOT FOUND\n'
  fi
else
  not_found "grep"
fi
printf 'pkg-config packages required by target configs: NONE DECLARED\n'
printf 'external C/C++ headers or libraries required by target configs: NONE DECLARED\n'

if command -v go >/dev/null 2>&1; then
  module_cache=$(GOTOOLCHAIN=local go env GOMODCACHE 2>/dev/null)
  if [ -n "$module_cache" ]; then
    printf '\ngo_module_cache: %s\n' "$module_cache"
    if [ -d "$module_cache" ]; then
      printf 'go_module_cache_directory: PRESENT\n'
    else
      printf 'go_module_cache_directory: NOT FOUND\n'
    fi
    if [ -r "$REPO_ROOT/go.mod" ]; then
      printf 'declared_module_cache_entries (read-only approximation):\n'
      awk '$1 ~ /^[[:alnum:]._-]+\/[[:alnum:]_.\/-]+$/ && $2 ~ /^v[0-9]/{print $1, $2}' "$REPO_ROOT/go.mod" |
      while read -r module_path module_version; do
        [ -n "$module_path" ] || continue
        if [ -d "$module_cache/$module_path@$module_version" ]; then
          cache_state='EXTRACTED'
        elif [ -f "$module_cache/cache/download/$module_path/@v/$module_version.zip" ]; then
          cache_state='ZIP CACHED'
        elif [ -f "$module_cache/cache/download/$module_path/@v/$module_version.mod" ]; then
          cache_state='MOD FILE ONLY'
        else
          cache_state='NOT FOUND'
        fi
        printf '%s %s: %s\n' "$module_path" "$module_version" "$cache_state"
      done
    fi
  else
    printf 'go_module_cache: NOT FOUND\n'
  fi
else
  printf 'go_module_cache: NOT FOUND (go command unavailable)\n'
fi

section "D. REPOSITORY STATE"
if command -v git >/dev/null 2>&1 && GIT_OPTIONAL_LOCKS=0 git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf 'absolute_path: %s\n' "$REPO_ROOT"
  branch=$(GIT_OPTIONAL_LOCKS=0 git -C "$REPO_ROOT" symbolic-ref --quiet --short HEAD 2>/dev/null)
  printf 'branch: %s\n' "${branch:-DETACHED}"
  printf 'commit: '
  GIT_OPTIONAL_LOCKS=0 git -C "$REPO_ROOT" rev-parse HEAD 2>&1 || printf 'NOT FOUND\n'
  printf 'commit_date: '
  GIT_OPTIONAL_LOCKS=0 git -C "$REPO_ROOT" show -s --format=%cI HEAD 2>&1 || printf 'NOT FOUND\n'
  printf 'git_describe: '
  GIT_OPTIONAL_LOCKS=0 git -C "$REPO_ROOT" describe --tags --always --dirty 2>&1 || printf 'NOT FOUND\n'
  worktree_state=$(GIT_OPTIONAL_LOCKS=0 git -C "$REPO_ROOT" status --porcelain --untracked-files=normal 2>/dev/null)
  if [ -z "$worktree_state" ]; then
    printf 'worktree: CLEAN\n'
  else
    printf 'worktree: DIRTY\n%s\n' "$worktree_state"
  fi
  printf 'submodule_status:\n'
  submodule_output=$(GIT_OPTIONAL_LOCKS=0 git -C "$REPO_ROOT" submodule status --recursive 2>&1)
  submodule_rc=$?
  if [ "$submodule_rc" -ne 0 ]; then
    printf 'COMMAND FAILED (exit=%s): %s\n' "$submodule_rc" "$submodule_output"
  elif [ -n "$submodule_output" ]; then
    printf '%s\n' "$submodule_output"
  else
    printf 'NONE\n'
  fi
else
  printf 'git_repository: NOT FOUND\n'
fi

section "E. TARGET ENTRY POINTS"
printf 'target_1_name: quic-go-policy-client\n'
printf 'target_1_expected_package: ./example/ack-policy-client\n'
if [ -f "$REPO_ROOT/example/ack-policy-client/main.go" ]; then
  printf 'target_1_source: PRESENT\n'
else
  printf 'target_1_source: NOT FOUND\n'
fi

printf '\ntarget_2_name: quic-go-server\n'
printf 'target_2_runner_expected_package: ./example/server\n'
if [ -f "$REPO_ROOT/example/server/main.go" ]; then
  printf 'target_2_runner_expected_source: PRESENT\n'
else
  printf 'target_2_runner_expected_source: NOT FOUND\n'
fi
printf 'target_2_current_branch_candidate_package: ./example\n'
if [ -f "$REPO_ROOT/example/main.go" ]; then
  printf 'target_2_current_branch_candidate_source: PRESENT\n'
  printf 'target_2_candidate_flags_detected:\n'
  grep -n 'flag\.\(String\|Bool\|Var\)' "$REPO_ROOT/example/main.go" 2>/dev/null || printf 'NOT FOUND\n'
else
  printf 'target_2_current_branch_candidate_source: NOT FOUND\n'
fi

printf '\nmain_packages_detected_under_example (static source scan):\n'
if command -v find >/dev/null 2>&1; then
  find "$REPO_ROOT/example" -maxdepth 3 -type f -name '*.go' -exec grep -l '^package main$' {} \; 2>/dev/null | sort
else
  not_found "find"
fi
printf 'NOTE: go list and go build were intentionally not executed.\n'

section "F. EXISTING TARGET BINARIES"
printf 'Candidate paths are intentionally limited to the repository and known experiment bin directories.\n'
candidate_bin_dirs=(
  "$REPO_ROOT"
  "$REPO_ROOT/bin"
  "$(dirname "$REPO_ROOT")/bin"
  "/home/ioio33/QUIC_project/bin"
)
if [ -n "${QUIC_PROJECT_BIN_DIR:-}" ]; then
  candidate_bin_dirs+=("$QUIC_PROJECT_BIN_DIR")
fi

seen_paths='|'
for candidate_dir in "${candidate_bin_dirs[@]}"; do
  for target_name in quic-go-server quic-go-policy-client; do
    target_path="$candidate_dir/$target_name"
    case "$seen_paths" in
      *"|$target_path|"*) continue ;;
    esac
    seen_paths="${seen_paths}${target_path}|"
    inspect_binary "$target_path"
  done
done

printf '\nQUIC_GO_BUILD_ENV_REPORT_END\n'
