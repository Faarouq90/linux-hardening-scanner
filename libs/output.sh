

record_pass() { PASS=$((PASS + 1)); printf '\n[PASS] %s\n' "$1"; }
record_warn() { WARN=$((WARN + 1)); printf '\n[WARN] %s\n' "$1"; }
record_fail() { FAIL=$((FAIL + 1)); printf '\n[FAIL] %s\n' "$1"; }
record_skip() { SKIP=$((SKIP + 1)); printf '\n[SKIP] %s\n' "$1"; }
record_err()  { ERR=$((ERR + 1));  printf '\n[ERR ] %s\n' "$1"; }

