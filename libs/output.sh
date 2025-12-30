

record_pass() { PASS=$((PASS + 1)); printf '[PASS] %s\n' "$1"; }
record_warn() { WARN=$((WARN + 1)); printf '[WARN] %s\n' "$1"; }
record_fail() { FAIL=$((FAIL + 1)); printf '[FAIL] %s\n' "$1"; }
record_skip() { SKIP=$((SKIP + 1)); printf '[SKIP] %s\n' "$1"; }
record_err()  { ERR=$((ERR + 1));  printf '[ERR ] %s\n' "$1"; }

