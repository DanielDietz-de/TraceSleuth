// Historical standalone web backend entrypoint intentionally retired.
//
// A separate, unauthenticated Go server lived in this directory in upstream
// SD-WAN Triage. Building that server is unsafe and no longer supported.
// The only supported runtime is cmd/sdwan-triage via the repository Makefile.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "Standalone SD-WAN Triage backend retired. Build TraceSleuth with: make build; run: ./build/tracesleuth -web")
	os.Exit(1)
}
