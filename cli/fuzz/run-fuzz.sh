#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

targets=(
  clipboard_command
  cli_args
  wire_message
  vault_blob
  pairing_files
  private_file
)

hours="${FERUSA_FUZZ_HOURS:-8}"
jobs="${FERUSA_FUZZ_JOBS:-1}"
max_len_default="${FERUSA_FUZZ_MAX_LEN:-4096}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="fuzz/runs/${run_id}"
mkdir -p "${run_dir}/logs" "${run_dir}/artifacts"

total_seconds="$(awk -v h="${hours}" 'BEGIN { printf "%d", h * 3600 }')"
if [ "${total_seconds}" -lt "${#targets[@]}" ]; then
  total_seconds="${#targets[@]}"
fi
seconds_per_target="$((total_seconds / ${#targets[@]}))"

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_odr_violation=0}:detect_leaks=0"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

summary="${run_dir}/summary.md"
status_file="${run_dir}/status.tsv"

cat > "${summary}" <<EOF
# Ferusa CLI Fuzz Run

- run_id: ${run_id}
- started_utc: $(date -u --iso-8601=seconds)
- hours_requested: ${hours}
- seconds_per_target: ${seconds_per_target}
- jobs: ${jobs}
- asan_options: ${ASAN_OPTIONS}
- rustc: $(rustc --version)
- cargo: $(cargo --version)
- cargo_fuzz: $(cargo fuzz --version 2>/dev/null || true)

## Targets

$(printf -- '- %s\n' "${targets[@]}")

## Results

EOF

printf "target\tstatus\tlog\tartifacts\n" > "${status_file}"
failures=0

echo "[ferusa-fuzz] run_dir=${run_dir}"
echo "[ferusa-fuzz] seconds_per_target=${seconds_per_target}"

echo "[ferusa-fuzz] cargo +nightly fuzz check"
if ! cargo +nightly fuzz check 2>&1 | tee "${run_dir}/logs/check.log"; then
  echo "check failed; see ${run_dir}/logs/check.log" | tee -a "${summary}"
  exit 1
fi

for target in "${targets[@]}"; do
  log="${run_dir}/logs/${target}.log"
  artifact_dir="${run_dir}/artifacts/${target}"
  mkdir -p "${artifact_dir}"

  max_len="${max_len_default}"
  case "${target}" in
    clipboard_command) max_len="${FERUSA_FUZZ_CLIPBOARD_MAX_LEN:-512}" ;;
    cli_args) max_len="${FERUSA_FUZZ_CLI_ARGS_MAX_LEN:-1024}" ;;
    pairing_files) max_len="${FERUSA_FUZZ_PAIRING_MAX_LEN:-1024}" ;;
    private_file) max_len="${FERUSA_FUZZ_PRIVATE_FILE_MAX_LEN:-4096}" ;;
    vault_blob) max_len="${FERUSA_FUZZ_VAULT_BLOB_MAX_LEN:-4096}" ;;
    wire_message) max_len="${FERUSA_FUZZ_WIRE_MESSAGE_MAX_LEN:-4096}" ;;
  esac

  fuzz_args=(
    "-max_total_time=${seconds_per_target}"
    "-max_len=${max_len}"
    "-artifact_prefix=${artifact_dir}/"
  )
  if [ "${jobs}" != "1" ]; then
    fuzz_args+=("-jobs=${jobs}")
  fi

  echo "[ferusa-fuzz] ${target}: ${seconds_per_target}s max_len=${max_len}"
  {
    echo "target=${target}"
    echo "started_utc=$(date -u --iso-8601=seconds)"
    echo "command=cargo +nightly fuzz run ${target} -- ${fuzz_args[*]}"
    cargo +nightly fuzz run "${target}" -- "${fuzz_args[@]}"
    status="$?"
    echo "finished_utc=$(date -u --iso-8601=seconds)"
    echo "status=${status}"
    exit "${status}"
  } 2>&1 | tee "${log}"
  status="${PIPESTATUS[0]}"

  if [ "${status}" -eq 0 ]; then
    printf "%s\tok\t%s\t%s\n" "${target}" "${log}" "${artifact_dir}" >> "${status_file}"
    echo "- ${target}: ok, log \`${log}\`" >> "${summary}"
  else
    failures=$((failures + 1))
    printf "%s\tfailed:%s\t%s\t%s\n" "${target}" "${status}" "${log}" "${artifact_dir}" >> "${status_file}"
    echo "- ${target}: failed (${status}), log \`${log}\`, artifacts \`${artifact_dir}\`" >> "${summary}"
    echo "" >> "${summary}"
    echo "Reproduce likely crash with:" >> "${summary}"
    echo "" >> "${summary}"
    echo "\`\`\`sh" >> "${summary}"
    echo "cargo +nightly fuzz run ${target} <artifact-path-from-log>" >> "${summary}"
    echo "\`\`\`" >> "${summary}"
  fi
done

cat >> "${summary}" <<EOF

## Output Paths

- logs: \`${run_dir}/logs/\`
- run artifacts: \`${run_dir}/artifacts/\`
- live corpus: \`fuzz/corpus/\`
- cargo-fuzz default artifacts: \`fuzz/artifacts/\`
- status table: \`${status_file}\`

## Finished

- finished_utc: $(date -u --iso-8601=seconds)
EOF

echo "[ferusa-fuzz] done"
echo "[ferusa-fuzz] summary=${summary}"
if [ "${failures}" -gt 0 ]; then
  echo "[ferusa-fuzz] failures=${failures}"
  exit 1
fi
