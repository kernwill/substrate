# Setup: from nothing to a working Claude Code session

Ordered. Do them in this sequence. Steps marked GATE should not be skipped past.

Estimated total: about 3 hours of hands-on work, plus two legal items that run in the background for days or weeks.

---

## Step 0. GATE: start the two legal items first

These have the longest lead times of anything in this document and they cost you nothing to start today.

1. Email or call a government contracts attorney. Scope: FAR 9.5 organizational conflict of interest exposure given your partner's role at the prime, and optimal funding vehicle. Bring the Cyber Lab contract terms.
2. Request a written position from your partner's employer on whether this venture falls outside his invention assignment. Blocking before the first real parser lands.

Also worth doing today because it takes an hour: get SOC 2 Type II quotes and pick a firm. It has a multi-month observation window and it is the long pole in the entire plan.

You can do everything below while those run. Phase 0 work is analysis and scaffolding, which creates little IP exposure.

---

## Step 1. Install the toolchain

On macOS with Homebrew:

```bash
brew install go golangci-lint opa gh jq
```

Verify:

```bash
go version          # want 1.23 or later
golangci-lint --version
opa version
gh --version
```

If you do not have Homebrew, install Go from go.dev/dl and the rest individually.

---

## Step 2. Create the local directory

Pick where your code lives. Common choice:

```bash
mkdir -p ~/code
cd ~/code
```

Then move the scaffold I generated into place:

```bash
mv ~/Downloads/substrate ~/code/substrate
cd ~/code/substrate
```

Confirm it looks right:

```bash
ls -la
# expect: CLAUDE.md, Makefile, go.mod, cmd/, internal/, docs/, rego/, scripts/, testdata/
```

---

## Step 3. Pick the real name and fix the module path

`substrate` is a placeholder. Run a trademark search before committing to it (uspto.gov TESS, plus a domain and GitHub org check).

Once decided, replace `kernwill` with your GitHub org and, if you renamed it, `substrate` with the real name:

```bash
cd ~/code/substrate
grep -rl 'kernwill' . | xargs sed -i '' 's|kernwill|your-github-org|g'
```

On Linux, drop the `''` after `-i`.

Verify nothing was missed:

```bash
grep -rn 'kernwill' . || echo "clean"
```

---

## Step 4. Initialize git and make the first commit

```bash
git init
git add -A
git commit -m "Scaffold: three-stage compiler skeleton with boundary enforcement

Architecture and invariants documented in CLAUDE.md.
Full requirements in docs/REQUIREMENTS.md."
```

---

## Step 5. Create the GitHub repo and push

Private for now. The open source pieces get split out later, deliberately, not by accident.

```bash
gh repo create your-github-org/substrate --private --source=. --remote=origin --push
```

If you prefer the web UI, create an empty private repo and then:

```bash
git remote add origin git@github.com:your-github-org/substrate.git
git branch -M main
git push -u origin main
```

---

## Step 6. Verify the scaffold actually works

```bash
go mod tidy
make boundaries      # should print "boundaries ok"
make build           # should produce bin/substrate
./bin/substrate      # should print a usage error and exit 2
```

`make test` will pass trivially (no tests yet). `make repro` will fail until `compile` is implemented, which is expected.

Confirm CI runs: check the Actions tab on GitHub after the push.

---

## Step 7. Vendor the FedRAMP rules dataset

This is the grammar the compiler targets. Nothing meaningful can be built without it.

```bash
cd ~/code
git clone https://github.com/FedRAMP/rules.git fedramp-rules
cd ~/code/substrate
mkdir -p internal/rules/data
cp ~/code/fedramp-rules/fedramp-consolidated-rules.json internal/rules/data/
cp ~/code/fedramp-rules/schemas/fedramp-consolidated-rules.schema.json internal/rules/data/
```

Record the version and a checksum so we can prove which dataset produced a given output:

```bash
jq -r '.version // .metadata.version // "unknown"' internal/rules/data/fedramp-consolidated-rules.json
shasum -a 256 internal/rules/data/*.json > internal/rules/data/CHECKSUMS.txt
cat internal/rules/data/CHECKSUMS.txt
```

Then read these three files before writing any ingestion code, in this order:

1. `~/code/fedramp-rules/AGENTS.md` — how the program office expects machines to consume the dataset
2. `~/code/fedramp-rules/RULES.md` — generated summary, for orientation
3. `~/code/fedramp-rules/schemas/fedramp-consolidated-rules.schema.json` — the actual contract

Commit:

```bash
git add -A && git commit -m "Vendor FedRAMP Consolidated Rules dataset with checksums"
```

---

## Step 8. Create the AWS sandbox

You need a throwaway AWS account for collector development. Not your production account, not the prime's.

1. Create a new AWS account, or a new Organizations member account.
2. Create a read-only role. Start from the AWS managed `SecurityAudit` and `ViewOnlyAccess` policies, then narrow. The final policy document gets published in our docs, so keep it clean from the start.
3. Stand up a small amount of realistic infrastructure: a VPC, a couple of S3 buckets (one deliberately misconfigured), an IAM role or two, CloudTrail on, KMS key with and without rotation. You need failing cases as much as passing ones.

Do not put real credentials anywhere in the repo. `.gitignore` already excludes `.env` and `testdata/live/`.

---

## Step 9. Build the fixtures

More important than they sound. They are the entire regression net and they should exist before the parsers.

```bash
mkdir -p testdata/fixtures/{minimal,terraform-basic,k8s-basic,failing-controls}
```

For each fixture, create:

- the input files (Terraform, Kubernetes manifests, workflow YAML)
- an `expected/` directory for golden output, empty for now
- a `NOTES.md` saying what this fixture is meant to catch

`failing-controls` matters most. A fixture where everything passes tells you almost nothing.

---

## Step 10. Start Claude Code

```bash
cd ~/code/substrate
claude
```

It reads `CLAUDE.md` automatically. First session, give it something bounded and verifiable. Suggested opening prompt:

> Read CLAUDE.md and docs/REQUIREMENTS.md sections 6 and 16.2, then read the vendored FedRAMP dataset at internal/rules/data/ along with its schema. Implement FR-1.1 and FR-1.2 only: a typed Go model of the dataset and schema validation that fails loudly on drift. Write tests first against the vendored file. Do not implement the differ or the query commands yet. Confirm `make boundaries` and `make test` pass before you finish.

Note the shape of that prompt: one narrow slice, explicit requirement IDs, tests first, and a stated definition of done. Claude Code does markedly better against that than against "build rules ingestion."

Work through `docs/TICKETS-PHASE0.md` in order.

---

## Step 11. Non-engineering work that must be owned

None of this happens on its own, and on a team this size it is probably a founder spending half their week. Name an owner for each:

| Item | Why it is urgent |
|---|---|
| Crosswalk analysis (T-001) | Gates the entire thesis |
| Ten discovery interviews | Assessor input should shape the backend format before it is built |
| SOC 2 Type II | Multi-month observation window, longest pole in the plan |
| FedRAMP partnership email to pete@fedramp.gov | NTC-0009 explicitly invites it. Costs an hour |
| Design partner acquisition | Needed before Phase 1 ends |
| Entity formation | Needed before the SOC 2 engagement |

---

## Quick reference

```bash
make check       # everything CI runs. Before every commit.
make boundaries  # architectural invariants
make test        # go test ./... -race
make build       # -> bin/substrate
make repro       # byte-identical output check
make golden      # golden-file tests only
```
