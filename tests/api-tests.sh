
set -u
BASE_URL="${BASE_URL:-http://localhost:3000}"
TEST_USER="${TEST_USER:-ci-user}"
TEST_PASS="${TEST_PASS:-CiTestPass123!}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

PASSED=0
FAILED=0
STATUS=""
BODY=""

call() {
  local method="$1" path="$2" data="${3:-}" token="${4:-}"
  local args=(-s -o "$TMP" -w '%{http_code}' -X "$method" "$BASE_URL$path")
  if [ -n "$data" ]; then
    args+=(-H 'Content-Type: application/json' --data-binary "$data")
  fi
  if [ -n "$token" ]; then
    args+=(-H "Authorization: Bearer $token")
  fi
  STATUS="$(curl "${args[@]}")"
  BODY="$(cat "$TMP")"
}

pass() { echo "PASS  $1"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL  $1  ($2)"; FAILED=$((FAILED + 1)); }

expect_status() {
  if [ "$STATUS" = "$2" ]; then pass "$1 -> $STATUS"; else fail "$1" "expected $2, got $STATUS, body: $BODY"; fi
}
expect_contains() {
  case "$BODY" in *"$2"*) pass "$1";; *) fail "$1" "body does not contain '$2': $BODY";; esac
}
expect_not_contains() {
  case "$BODY" in *"$2"*) fail "$1" "body must not contain '$2': $BODY";; *) pass "$1";; esac
}

b64url() { printf '%s' "$1" | base64 | tr -d '=\n' | tr '+/' '-_'; }

echo "Testing $BASE_URL"

call POST /api/ping '{"message":"ping"}'
expect_status   "POST /api/ping {ping} without token" 200
expect_contains "ping returns pong" '"reply":"pong"'

call POST /api/ping '{"message":"hello"}'
expect_status "POST /api/ping {hello} is rejected" 400

call POST /api/ping '{bad json'
expect_status "POST /api/ping malformed JSON is rejected" 400

call GET /api/data
expect_status "GET /api/data without token" 401

call GET /api/data "" "not.a.jwt"
expect_status "GET /api/data with garbage token" 401

NONE_TOKEN="$(b64url '{"alg":"none","typ":"JWT"}').$(b64url '{"sub":"1","username":"admin"}')."
call GET /api/data "" "$NONE_TOKEN"
expect_status "GET /api/data with forged alg=none token" 401

call POST /api/posts '{"content":"x"}'
expect_status "POST /api/posts without token" 401

call POST /auth/login '{}'
expect_status "POST /auth/login without credentials" 400

call POST /auth/login "{\"username\":\"$TEST_USER\",\"password\":\"definitely-wrong\"}"
expect_status "POST /auth/login wrong password" 401

call POST /auth/login "{\"username\":\"$TEST_USER' OR '1'='1\",\"password\":\"x\"}"
expect_status "POST /auth/login SQL injection attempt" 401

call POST /auth/login "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}"
expect_status   "POST /auth/login valid credentials" 200
expect_contains "login returns access_token" '"access_token"'
TOKEN="$(printf '%s' "$BODY" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"

if [ -z "$TOKEN" ]; then
  fail "token extraction" "no token in login response, remaining tests need it"
  echo "Passed: $PASSED, Failed: $FAILED"
  exit 1
fi

call POST /api/posts '{"content":"<script>alert(1)</script>"}' "$TOKEN"
expect_status "POST /api/posts with token" 201

call GET /api/data "" "$TOKEN"
expect_status       "GET /api/data with valid token" 200
expect_contains     "XSS payload is escaped in response" '&lt;script&gt;'
expect_not_contains "raw <script> tag is absent from response" '<script>'
echo "Passed: $PASSED, Failed: $FAILED"
[ "$FAILED" -eq 0 ]
