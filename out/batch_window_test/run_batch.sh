#!/usr/bin/env bash
# Window-mode A/B experiment driver.
# Runs each challenge in challenges.tsv once with the configuration:
#   --llm-provider openai --model gpt-5.2 --max-steps 30 --rag-mode original
# Logs go to per-challenge files under logs/<slug>.log.
# Override CONFIG_LABEL to tag a run set (e.g. "baseline" or "obs7").

set -u

cd "$(dirname "$0")/../.."

CONFIG_LABEL="${CONFIG_LABEL:-baseline}"
EXTRA_FLAGS="${EXTRA_FLAGS:-}"
LOG_DIR="out/batch_window_test/logs_${CONFIG_LABEL}"
SUMMARY_FILE="out/batch_window_test/summary_${CONFIG_LABEL}.tsv"
TSV="out/batch_window_test/challenges.tsv"

mkdir -p "$LOG_DIR"
echo -e "slug\texit_code\tflag_seen\tflag\twall_seconds" > "$SUMMARY_FILE"

# Skip TSV header
tail -n +2 "$TSV" | while IFS=$'\t' read -r name url description hints; do
    [ -z "$name" ] && continue
    slug=$(printf "%s" "$name" \
        | tr '[:upper:]' '[:lower:]' \
        | tr -c '[:alnum:]' '_' \
        | sed -E 's/_+/_/g; s/^_+|_+$//g')
    log_file="$LOG_DIR/${slug}.log"

    echo "=== [$CONFIG_LABEL] $name ($slug) ===" | tee -a "$log_file"
    start=$(date +%s)

    .venv/bin/python -m ctf_solver.runner \
        --llm-provider openai \
        --model gpt-5.2 \
        --max-steps 30 \
        --rag-mode original \
        --challenge-name "$slug" \
        --challenge-url "$url" \
        --description "$description" \
        ${hints:+--hints "$hints"} \
        $EXTRA_FLAGS \
        >> "$log_file" 2>&1
    rc=$?

    end=$(date +%s)
    wall=$((end - start))

    # Grade via the runner's own [FLAG DETECTED] marker (ctf_solver/log_grader).
    # That marker is printed only for strict-regex-confirmed flags, so this
    # grade agrees with RunTracker.confirmed_flags_found by construction —
    # no separate flag regex to drift. Replaces the old case-sensitive grep
    # that missed MetaCTF{ and counted false positives like try{...}.
    grade_line=$(.venv/bin/python -m ctf_solver.log_grader "$log_file")
    flag_seen=$(printf "%s" "$grade_line" | cut -f1)
    flag=$(printf "%s" "$grade_line" | cut -f2)

    printf "%s\t%d\t%s\t%s\t%d\n" "$slug" "$rc" "$flag_seen" "$flag" "$wall" >> "$SUMMARY_FILE"
    echo "    exit=$rc flag_seen=$flag_seen wall=${wall}s" | tee -a "$log_file"
done

echo
echo "=== Done ($CONFIG_LABEL) ==="
echo "Summary: $SUMMARY_FILE"
echo
column -t -s $'\t' "$SUMMARY_FILE"
