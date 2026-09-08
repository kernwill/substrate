# Fixture: minimal

Smallest input that exercises the full pipeline end to end.

Fixtures are the regression net for this project and matter more than they look.
Every fixture directory must contain:

- input files (Terraform, Kubernetes manifests, workflow YAML)
- `expected/` with the golden output artifacts
- `NOTES.md` explaining what this fixture is meant to catch

Never edit `expected/` by hand to make a test pass. Regenerate it deliberately
and review the diff, because that diff is a change in what we assert to the
federal government.
