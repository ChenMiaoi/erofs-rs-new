#!/usr/bin/env bash
# Long-running, deterministic EROFS superblock metadata fuzzing demo.
# Each round uses a fresh seed and shares one content-addressed corpus.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: examples/metadata-fuzz.sh IMAGE [CORPUS] [options]

Continuously fuzz EROFS superblock metadata with erofs-cli campaign. The
interactive dashboard is enabled by default when stdout is a terminal. Every
round writes its recipe and report below CORPUS/campaigns and contributes to
CORPUS/novelty.json; materialized images are content-addressed below
CORPUS/samples/sha256.

Arguments:
  IMAGE                 immutable source EROFS image
  CORPUS                output corpus (default: ./metadata-fuzz-corpus)

Options:
  --duration-seconds N  fuzz continuously until this total runtime elapses
  --cases N             fuzz exactly this many generated cases, then stop
  --samples-per-round N cases generated per deterministic seed (default: 4096)
  --max-mutations N     maximum mutations in generated combinations (default: 4)
  --funnel POLICY       novelty, all, or materialize-only (default: novelty)
  --prepare             build workspace prerequisites after opening the dashboard
  --workspace PATH      repository/workspace containing oracle artifacts (default: repo root)
  --no-tui              disable the campaign dashboard
  -h, --help            show this help

Prerequisites for --funnel novelty or all:
  make all

  examples/metadata-fuzz.sh build/rootfs.erofs --cases 10 --funnel all
Examples:
  examples/metadata-fuzz.sh build/rootfs.erofs
  examples/metadata-fuzz.sh build/rootfs.erofs /srv/erofs-corpus \
      --duration-seconds 604800 --samples-per-round 8192 --funnel all
EOF
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=
corpus="$repo_root/build/metadata-fuzz-corpus"
duration_seconds=86400
cases=
samples_per_round=4096
max_mutations=4
funnel=novelty
workspace="$repo_root"
prepare=0
no_tui=0

while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --duration-seconds) duration_seconds=${2:?missing value for --duration-seconds}; shift 2 ;;
        --cases) cases=${2:?missing value for --cases}; shift 2 ;;
        --samples-per-round) samples_per_round=${2:?missing value for --samples-per-round}; shift 2 ;;
        --max-mutations) max_mutations=${2:?missing value for --max-mutations}; shift 2 ;;
        --funnel) funnel=${2:?missing value for --funnel}; shift 2 ;;
        --workspace) workspace=${2:?missing value for --workspace}; shift 2 ;;
        --prepare) prepare=1; shift ;;
        --no-tui) no_tui=1; shift ;;
        -*) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
        *)
            if [[ -z $image ]]; then image=$1
            elif [[ $corpus == "$repo_root/build/metadata-fuzz-corpus" ]]; then corpus=$1
            else printf 'unexpected argument: %s\n' "$1" >&2; usage >&2; exit 2
            fi
            shift
            ;;
    esac
done

[[ -n $image ]] || { usage >&2; exit 2; }
((prepare)) || [[ -f $image ]] || { printf 'image does not exist: %s\n' "$image" >&2; exit 2; }
[[ -z $cases || $cases =~ ^[1-9][0-9]*$ ]] || { printf 'cases must be a positive integer\n' >&2; exit 2; }
[[ -n $cases || $duration_seconds =~ ^[1-9][0-9]*$ ]] || { printf 'duration must be a positive integer\n' >&2; exit 2; }
[[ $samples_per_round =~ ^[1-9][0-9]*$ ]] || { printf 'samples per round must be a positive integer\n' >&2; exit 2; }
[[ $max_mutations =~ ^[1-9][0-9]*$ ]] || { printf 'max mutations must be a positive integer\n' >&2; exit 2; }
case "$funnel" in novelty|all|materialize-only) ;; *) printf 'invalid funnel: %s\n' "$funnel" >&2; exit 2 ;; esac

mkdir -p "$corpus"
offset_file="$corpus/next-case-offset"
case_offset=0
if [[ -n $cases && -f $offset_file ]]; then
    case_offset=$(<"$offset_file")
    [[ $case_offset =~ ^[0-9]+$ ]] || { printf 'invalid case offset state: %s\n' "$offset_file" >&2; exit 2; }
fi
# Persist the base seed so resuming with a saved next-case-offset continues
# the same deterministic case stream instead of skipping into a fresh one.
seed_file="$corpus/base-seed"
if [[ -f $seed_file ]]; then
    base_seed=$(<"$seed_file")
    [[ $base_seed =~ ^[0-9]+$ ]] || { printf 'invalid base seed state: %s\n' "$seed_file" >&2; exit 2; }
else
    base_seed=$(date +%s)
    printf '%s\n' "$base_seed" > "$seed_file"
fi
# Always rebuild the workspace binary: fuzz sessions must run the checked-out
# dashboard rather than a possibly stale target/debug executable.
cli=${EROFS_CLI:-$repo_root/target/debug/erofs-cli}
if [[ -z ${EROFS_CLI:-} ]]; then
    cargo build -q -p erofs-cli -p erofs-lab --manifest-path "$repo_root/Cargo.toml"
elif [[ ! -x $cli ]]; then
    printf 'EROFS_CLI is not executable: %s\n' "$cli" >&2
    exit 2
fi

# Start with classified seeds: valid-preserving timestamp changes and an
# explicitly invalid magic value. Remaining fields stay exploratory.
fields=(
    erofs.superblock.epoch
    erofs.superblock.fixed_nsec
    erofs.superblock.build_time
    erofs.superblock.magic
    erofs.superblock.checksum
    erofs.superblock.feature_compat
    erofs.superblock.blkszbits
    erofs.superblock.inos
    erofs.superblock.blocks_lo
    erofs.superblock.meta_blkaddr
    erofs.superblock.xattr_blkaddr
    erofs.superblock.uuid
    erofs.superblock.volume_name
    erofs.superblock.feature_incompat
    erofs.superblock.extra_devices
    erofs.superblock.devt_slotoff
    erofs.superblock.dirblkbits
    erofs.superblock.xattr_prefix_count
    erofs.superblock.xattr_prefix_start
    erofs.superblock.packed_nid
)

start=$(date +%s)
round=0
while [[ -n $cases && $round -eq 0 ]] || { [[ -z $cases ]] && (( $(date +%s) - start < duration_seconds )); }; do
    seed=$((base_seed + round))
    if [[ -n $cases ]]; then
        remaining=case-bounded
        samples_this_round=$cases
        # Case mode ends only after the requested number of generated cases.
        # Individual oracle limits still bound a hung Rust reader, fsck, or QEMU guest.
        wall_time_ms=0
    else
        remaining=$((duration_seconds - ($(date +%s) - start)))
        ((round > 0 && remaining <= 1)) && break
        samples_this_round=$samples_per_round
        wall_time_ms=$((remaining * 1000))
        ((wall_time_ms > 900000)) && wall_time_ms=900000
    fi
    case "$funnel" in
        materialize-only) oracle_runs_this_round=0 ;;
        *) oracle_runs_this_round=$((samples_this_round * 3)) ;;
    esac

    command=("$cli" campaign run "$image" --output-dir "$corpus" --seed "$seed"
        --mode corrupt --integrity recalculate --funnel "$funnel"
        --max-samples "$samples_this_round" --max-mutations "$max_mutations"
        --max-image-bytes 1073741824 --max-oracle-runs "$oracle_runs_this_round"
        --case-offset "$case_offset"
        --wall-time-ms "$wall_time_ms" --workspace "$workspace")
    ((prepare && round == 0)) && command+=(--prepare)
    for field in "${fields[@]}"; do command+=(--field "$field"); done
    ((no_tui)) && command+=(--no-tui)
    printf 'metadata fuzz round=%d seed=%d bound=%s corpus=%s\n' \
        "$round" "$seed" "$remaining" "$corpus"
    "${command[@]}"
    if [[ -n $cases ]]; then
        printf '%s\n' "$((case_offset + cases))" > "$offset_file"
    fi
    ((round += 1))
done

printf 'metadata fuzz complete: rounds=%d corpus=%s\n' "$round" "$corpus"
