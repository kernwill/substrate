// Package backends maps the IR to specific compliance frameworks and emits
// their artifacts.
//
// CONTRACT:
//   - This is the ONLY place framework-specific logic may live.
//   - Backends depend on ir. Nothing depends on backends.
//   - Adding a framework must not require changes to frontend or ir. If it
//     does, record it: that is a leak in the abstraction and the leak is the
//     most important measurement in the project (see docs/REQUIREMENTS.md,
//     Phase 4).
package backends
