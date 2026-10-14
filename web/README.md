# TraceSleuth web interface

TraceSleuth is the supported and maintained successor to the imported
SD-WAN Triage Web Application. The **only supported backend runtime** is
the authenticated embedded application in the repository root command at
`cmd/sdwan-triage`. Its published executable is named `tracesleuth`.

## Build and run

From the repository root:

```bash
make build
./build/tracesleuth -web -no-browser
```

This uses the version from `VERSION`, embeds the React frontend and GeoIP data,
and starts the hardened local-only backend at `http://127.0.0.1:8080`.

Initialize the administrator explicitly before the first authenticated start
using the `TRACESLEUTH_BOOTSTRAP_ADMIN_USERNAME` and
`TRACESLEUTH_BOOTSTRAP_ADMIN_PASSWORD` environment variables described in the
[root README](../README.md). No universal default password exists.

To develop the frontend separately, start the canonical TraceSleuth backend
first and then run:

```bash
cd web/frontend
npm ci
npm run dev
```

Vite serves the UI at `http://localhost:3000` and proxies HTTP and WebSocket
requests to the local backend. The `/api/ws` proxy preserves the original Host
so strict browser WebSocket Origin checks still work.

`web/build.sh` is a compatibility wrapper for `make build`; cross-platform
release builds use `make release` or the repository release workflow.

## Retired upstream implementation

`web/backend/` and the committed historical `web/releases/v4.3.0/` artifacts
are unmaintained upstream material, **not** a supported TraceSleuth runtime.
The legacy `go run .` entrypoint is deliberately disabled. Do **not** execute
or redistribute the historical binaries: the old server included unbounded
file uploads, user-controlled filesystem paths, and no modern authenticated
API protection. The historical files remain solely for provenance.

PCAP and optional TLS key log files can contain sensitive information.
Use the root application and consult [SECURITY.md](../SECURITY.md) before
any remote deployment. TraceSleuth remains pre-production.
