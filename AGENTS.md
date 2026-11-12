# Repository Guidelines

sealbound seals secrets for storage in an application's own database: with a public key, bound to the record each belongs to, with key rotation. It is a small TypeScript library, published to npm as an ES module for Node.js 22 or later, Bun, Deno, browsers and Workers.

## The format

A sealed value is a libsodium sealed box (`crypto_box_seal`) of a version byte, the context's digest and the value. The README states the digest, the key id and the text form exactly, and that statement is the contract: values sealed by any released version must keep opening. A change to the layout gets a new version byte, or a new text prefix when the outer box changes, and the opener keeps reading the old one. `tests/sealbound.test.ts` holds a value libsodium sealed that every version must open; never regenerate it to make a change pass.

The primitives come from the noble libraries and nothing here reimplements one. Putting them together into a sealed box is this library's own code, checked against libsodium both ways in the tests. The library uses only what every runtime has (`atob`, `btoa`, `TextEncoder`, the Web Crypto random source through noble): no `node:` module and no `Buffer` in `src`.

Every public function checks what it is given, because a caller without types can pass anything: a string where bytes go would be sealed as zeros. The checks are the small type guards at the top of `src/index.ts`.

## Dependencies

The runtime dependencies are the cryptography, so they are caret ranges: whoever installs the library gets their security patches without waiting for a release here. `pnpm audit --prod` reports nothing: CI and the release both run it. Development dependencies are pinned exactly.

## Checks

`pnpm build`, `pnpm check` (format, lint and unused code), `pnpm check-types`, `pnpm test` and `pnpm check-package` (publint and attw) pass before every commit. Build first: the lint reads the types of the built package that `scripts/smoke.mjs` imports. CI runs all of them on every push, and runs the built package on Node.js, Bun and Deno (`scripts/smoke.mjs`). `pnpm fix` writes the formatting and the safe fixes. Never disable a lint rule to pass it.

## Tests

Tautological tests are harmful. For each test, name a production change that would make it fail; otherwise delete it. Assert observable behavior against independent expectations, never an echo of a fixture, mock response or the production arithmetic itself.

Prefer property-based tests, with [Hegel](https://hegel.dev/). libsodium (`libsodium-wrappers`, a development dependency) is the oracle for the format: what it seals must open here, and what is sealed here must open there. Keep example-based tests for fixed contracts and known regressions. A fixed figure in an assertion cites where it comes from, in the test's title or a comment beside it; `pnpm check` refuses an uncited one (`honest-tests/literal-needs-source`), along with snapshots and mock call counts. Never cite a source the value doesn't come from to get past it.

## Comments

A comment sits on the code it explains: never a file header, never above or among the imports (`file-comments/no-head-comments`).

## Changes

Every change reaches `main` through a pull request, merged with a squash once CI passes; `main` is protected and nobody pushes to it directly. A commit message is a short plain subject that says what changed, with no body.

## Releases

Bump `version` in `package.json` and add its entry to `CHANGELOG.md`, then push a `vX.Y.Z` tag that matches. `.github/workflows/publish.yml` publishes it with npm's trusted publishing and a provenance statement; no token is stored anywhere. The workflow has three jobs with one permission each: the job that runs the toolchain can't publish, and the job that publishes runs none of the project's code. The publish job runs in the `release` environment, so it waits for the maintainer's approval on GitHub before anything reaches npm. Every action in a workflow is pinned to a full commit SHA, with its version in a comment; Dependabot moves them. A breaking change to what any function accepts, or to what a sealed value contains, is a major version.
