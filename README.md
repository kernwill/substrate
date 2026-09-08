# substrate

A compliance compiler.

Reads infrastructure-as-code, cluster manifests, CI configuration, identity
policy, and cloud control plane state. Normalizes them into an evidence graph
keyed on NIST 800-53 control families. Emits regulatory artifacts from that
graph, and gates CI so compliance drift fails the build.

First target: FedRAMP 20x under the Consolidated Rules for 2026.

Status: pre-alpha. Nothing works yet.

## Documentation

| Document | Purpose |
|---|---|
| `CLAUDE.md` | Operational context. Architecture, invariants, stack, commands |
| `docs/SETUP.md` | Ordered setup from an empty directory to a working session |
| `docs/REQUIREMENTS.md` | Full end-to-end requirements |
| `docs/TICKETS-PHASE0.md` | Phase 0 work broken into verifiable tickets |
| `docs/adr/` | Architecture decision records |

## Architecture

    frontend  ->  ir  ->  backends
    (parse)      (IR)     (emit)

The IR is framework-agnostic and keyed on 800-53. Framework logic lives only in
backends. This boundary is enforced in CI by `scripts/check-boundaries.sh` and
is the reason the project can add a second framework cheaply. It is not a style
preference.

## Commands

    make check       # everything CI runs
    make boundaries  # architectural invariants
    make test
    make build
    make repro       # byte-identical output check

## License

Not yet determined. The rules ingestion layer and Rego evaluation modules are
intended for Apache 2.0 release; the rest stays proprietary. See
`docs/REQUIREMENTS.md` section 26.
# substrate
