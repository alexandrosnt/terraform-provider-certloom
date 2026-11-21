#!/bin/sh
# Starts a throwaway certloomd with PostgreSQL for the acceptance tests and
# writes CERTLOOM_ENDPOINT and CERTLOOM_TOKEN to .testserver/env.
#
#   CERTLOOM_SRC=../certloom scripts/testserver.sh start
#   . .testserver/env && TF_ACC=1 go test ./...
#   scripts/testserver.sh stop
#
# Needs Docker and Go. CERTLOOM_SRC points at a certloom checkout.
set -eu

dir=$(pwd)/.testserver
pg=certloom-tf-acc-pg
pgport=${TESTSERVER_PG_PORT:-55439}
apiport=${TESTSERVER_PORT:-18443}
agentport=${TESTSERVER_AGENT_PORT:-18444}
owner_pw=acc-owner-not-secret
app_pw=acc-app-not-secret

stop() {
	if [ -f "$dir/certloomd.pid" ]; then
		kill "$(cat "$dir/certloomd.pid")" 2>/dev/null || true
	fi
	docker rm -f "$pg" >/dev/null 2>&1 || true
	rm -rf "$dir"
}

start() {
	: "${CERTLOOM_SRC:?set CERTLOOM_SRC to a certloom checkout}"
	stop
	mkdir -p "$dir"
	bin="$dir/certloomd$(go env GOEXE)"
	# certloom pins its own Go toolchain; let go fetch it for this build.
	(cd "$CERTLOOM_SRC" && GOTOOLCHAIN=auto go build -o "$bin" ./cmd/certloomd)

	docker run -d --name "$pg" -p "127.0.0.1:$pgport:5432" \
		-e POSTGRES_USER=certloom_owner -e POSTGRES_PASSWORD="$owner_pw" -e POSTGRES_DB=certloom \
		postgres:18-alpine >/dev/null
	i=0
	until docker exec "$pg" pg_isready -U certloom_owner -d certloom >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -lt 60 ] || { echo "postgres did not start" >&2; exit 1; }
		sleep 1
	done

	CERTLOOM_MIGRATE_DATABASE_URL="postgres://certloom_owner:$owner_pw@127.0.0.1:$pgport/certloom?sslmode=disable" "$bin" migrate
	docker exec "$pg" psql -q -U certloom_owner -d certloom -c "ALTER ROLE certloom_app LOGIN PASSWORD '$app_pw'"

	db="postgres://certloom_app:$app_pw@127.0.0.1:$pgport/certloom?sslmode=disable"
	token=$(CERTLOOM_DATABASE_URL="$db" "$bin" bootstrap --org tf-acc --ttl 12h 2>/dev/null)
	kek=$("$bin" gen-kek)

	CERTLOOM_DATABASE_URL="$db" CERTLOOM_KEK="$kek" CERTLOOM_LISTEN="127.0.0.1:$apiport" \
		CERTLOOM_AGENT_LISTEN="127.0.0.1:$agentport" CERTLOOM_LOG_LEVEL=warn \
		"$bin" serve >"$dir/certloomd.log" 2>&1 &
	echo $! >"$dir/certloomd.pid"

	i=0
	until curl -fsS "http://127.0.0.1:$apiport/readyz" >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -lt 60 ] || { cat "$dir/certloomd.log" >&2; exit 1; }
		sleep 1
	done
	umask 077
	printf 'export CERTLOOM_ENDPOINT=http://127.0.0.1:%s\nexport CERTLOOM_TOKEN=%s\n' "$apiport" "$token" >"$dir/env"
	echo "certloomd ready on http://127.0.0.1:$apiport; source $dir/env"
}

case "${1:-}" in
start) start ;;
stop) stop ;;
*) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
