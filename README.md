# Maintenance Man (mm)

Maintenance Man(ager) is a CLI helper that makes the routine maintenance of your personal projects simpler.

## What

`mm` is a CLI tool that assists in the maintenance of configured projects. It supports the following core workflow: 

1. Scan project(s) for vulnerabilities, dependency updates and exposed secrets.
2. Update dependencies, validate via the target project's unit/integration/component tests, and create jj commits for passing updates.
3. Build the deploy artefacts for the updated project(s), if relevant.
4. Deploy updated application(s) and validate via healthchecking.

## Why 

Maintenance Manager was written to solve the following chain of problems: 

1. Coding agents make it easy to create new projects using different frameworks and coding langauges.
2. It is hard to remember the specific incantations for test/build/deploy when moving between these diverse projects.
3. Vulnerability detection and dependency updating are crtically important but tedious to perform.
4. I don't want to configure a full CI/CD pipeline for my personal projects.

## Usage 

* Clone the project
* Run `uv tool install -e .` to make the `mm` command globally available
* See `mm --help` for the full command reference

Common update flows:

```bash
mm update                 # batch update all configured projects
mm update api             # interactive update flow for one project
mm update api worker      # batch update only the named projects
mm update -n api worker   # batch update all except api and worker
mm update api -n worker   # same exclusion mode; flag position does not matter
```

`mm scan` fails a project when its vulnerability scan or outdated check fails, and keeps that project's previously saved result. Scanning several projects continues with the rest, then exits with the error code if any project failed. `mm scan` also fails a project when `bun outdated`, Maven or `uv audit` output is not in a shape mm recognises, or when `uv audit` reports a different number of advisories than mm read.

mm saves one fix per package. For each advisory it takes the lowest listed fix above the installed version, and for the package the highest of those. That version is saved only on the advisories it is known to fix, meaning it equals one of the advisory's listed fixes or is at or above every one of them. Versions are compared only when their qualifiers match, such as `-jre` or `.Final`; uv versions follow PEP 440. A package whose advisories name more than one installed version gets no fix. An advisory mm cannot fix is listed without a fix. Completing an advisory is provisional: the next `mm scan` is the proof.

`mm update` and `mm resolve` require jj.

```text
Usage: mm COMMAND

Config-driven CLI for routine software project maintenance.

Commands:
  build: Build a project's artefacts.
  deploy: Deploy a project.
  init: Initialise MM_HOME (default ~/.mm) and its skeleton config.
  list, status, st: List all configured projects with scan findings summary.
  resolve: Work through failed findings for a project.
  scan: Scan projects for vulnerabilities and available updates.
  sync: Sync local main with remote for one, many, or all configured projects.
  test: Run a project's test suite.
  todo: Show TODO.md items for projects.
  update: Apply updates from scan results to one, many, or all projects.
  --help, -h: Display this message and exit.
  --version, -v: Display application version.
```

## Output and subprocess logs

Build, test, deploy, update and resolve hide successful subprocess logs by default. Failed commands replay stdout and stderr once on stderr. Add `--verbose` to stream both child streams live to stderr, including successful commands. Timeouts and interruptions expose partial logs and ask the command to terminate, escalating to SIGKILL after two seconds. Successful output is hidden, and so are prompts the command writes to stdout or stderr, because both streams go to temporary files until the command ends; only a prompt that opens `/dev/tty` appears. Ctrl-C still reaches the command. Run interactive scripts with `--verbose`, or have them write their prompt to `/dev/tty`. Logging ends when the command exits; services started in the background should own their log destinations. Protocol queries keep their output captured for parsing.

Terminal output uses grouped, borderless records. Status words remain readable without colour. Narrow terminals abbreviate long fields and omit secondary columns; pipe the command to retain full values. Footers name hidden columns and may wrap to preserve that information. `NO_COLOR`, `TERM=dumb` and an unset `TERM` disable colour. Progress appears only on a stderr terminal after 500 ms, never while the command can read the terminal, and disappears on completion.

When stdout is redirected, records are headerless TSV. Warnings, prompts, errors, progress and totals go to stderr. Help and version remain human-readable text. Field order:

| Command or record | Fields |
| --- | --- |
| `mm list` | project, package_manager, vulnerabilities, updates, secrets, scanned_at, built_at, build_status, deployed_at, deploy_status |
| `mm list --detail`, `mm scan` findings | project, kind, package or path, installed, target, severity or tier, identifier, published_at, status, reason |
| Outcome (`update`, `resolve`, `build`, `test`, `deploy`, `sync`) | project, operation, status, subject, installed, target, reason |
| `mm todo` | project, line_number, text |

Timestamps use exact ISO 8601 in pipes and short relative values on a terminal. Unknown counts use `-`; known empty counts use `0`. Other absent values use `-`, with explicit reasons such as `never` or `not deployable` where relevant. TSV fields escape backslash, tab, carriage return and newline as `\\`, `\t`, `\r` and `\n`; other ASCII and C1 controls use `\xNN`, and Unicode line/paragraph separators use `\u2028`/`\u2029`. Bracketed text is literal. The reason field is a human-readable explanation.

A passed package update and promotion to local main are separate outcomes. A failed build records deployment as skipped.

## Breaking changes and upgrading

`mm update` and `mm resolve` no longer open pull requests or need `gh`; resolve promotes to local `main`. A project without a configured test phase now fails `mm update` with exit code 4 instead of warning. `mm resolve --continue` with no saved failure exits 1. `mm scan` no longer prunes bookmarks. Saved scans gain `resolve_repair_base` and Gradle blocked rows. Saved scans hold one lifecycle state per finding and record the package manager they were taken with. mm refuses as corrupt scan results any scan saved by an earlier version, and any scan taken under a manager other than the project's, until `mm scan <project>` replaces it.

Finish or abandon a paused `mm resolve` before upgrading, because its saved state goes with the old scan. Before the first `mm update` or `mm resolve` after upgrading, run `mm scan` for every project, or delete its saved scan under `~/.mm/scan-results`. `mm update` and `mm resolve` report an older scan as `corrupt scan results` and name the command to run; `mm list` skips it with a warning. Rescanning also replaces Gradle targets that the previous engine never age-checked or validated. If the old pull-request flow left a pull request open, merge or close it before rescanning. `~/.mm/gradle-runs` and `~/.mm/gradle-contexts` are unused and can be deleted.

## Application contract 

This tool was written with some expectations about how configured projects are written:

* Projects are local to device
* Projects use one of [supported package managers](#supported-language-and-tools)
* Projects follow a unit / integration / component testing hierarchy.
* Projects manage their own test dependencies (e.g. testcontainers, pytest-docker)
* Build and deploy workflows are encoded in dedicated scripts within the projects.

Not strictly enforced by tool but expected as best practice: 

* Deployable projects expose a healthcheck endpoint
* An external `healthchecker` service exists [i.e. mm does not hold knowledge on how indvidiual project's healthchecks are exposed]

## Configuration

Configuration defaults to your user home - `~/.mm/` - run `mm init` to create this and a minimal `config.toml`

Set `MM_HOME` before starting mm to use a separate configuration and state directory, for example `MM_HOME=/tmp/mm-demo uv run mm init`. This redirects saved scans, activity, publication caches and update workspaces as well as `config.toml`. Relative paths resolve from the invocation directory. An unset or empty value uses `~/.mm`.

Configuration is done per project - with a header of `[projects.project-name]`

```toml
[projects.example]
path = "/home/myuser/dev/example" # required, the path to the project
package_manager = "uv" # required (one of: mvn, uv, bun, gradle), which package manager does the project use 
test_unit = "uv run pytest" # optional, the command to run unit tests
test_integration = "uv run pytest -m integration" # optional, the command to run integration tests
test_component = "uv run pytest -m docker" # optional, the command to run component tests
build_command = "" # optional, path to a script defining the build process, relative to projects home dir
deploy_command = "scripts/deploy.sh" # optional, path to script defining the deploy process, relative to projects home dir
scan_skip_dirs = ["tests/fixtures"] # optional, an array of relative directories that trivy should ignore in its scans.
```

Test, build and deploy commands run through `/bin/bash` in the project directory, so shell syntax such as `&&`, pipes, redirects and quoting works. A pipeline's status is its last command's status unless the command sets `set -o pipefail`. Test commands were previously split into arguments without a shell, so a test command containing literal shell characters may now need quoting.

Automatic updates need at least one test phase. A project without one fails before mm changes anything.

The following defaults can be globally configured: 

```toml
[defaults]
min_version_age_days = 7 # how old dependencies should be before trivy reports the update, guards against package takeover attacks.
healthcheck_url = "http://healthchecker:8080" # the URL of your healthchecker service (if using)
```

## Gradle projects

`package_manager = "gradle"` targets a project that uses a Gradle wrapper and a version catalogue at `gradle/libs.versions.toml`. mm runs the project's own `./gradlew`. The project must supply its Gradle wrapper and build scripts; mm does not install plugins or change that setup.

### Required project setup

The project must apply these two plugins, pinned to these versions, in its root build script. mm sets the CycloneDX output locations itself, so the project configures none:

```kotlin
plugins {
    id("nl.littlerobots.version-catalog-update") version "1.1.1"
    id("org.cyclonedx.bom") version "3.4.1"
    // Retain the project's existing plugins.
}
```

Configure the test commands as for any other project, for example `test_unit = "./gradlew :app:testDebugUnitTest"`.

Standard generated build and cache outputs must already be ignored by the repository, because mm commits every tracked change left after the configured tests pass.

Export the Android SDK location before running `mm update`. `mm update` applies changes inside a throwaway jj workspace under `~/.mm/workspaces/`, and a jj workspace checks out tracked files only. `local.properties` is conventionally untracked, so `sdk.dir` is not available there and an Android build cannot find the SDK. Export `ANDROID_HOME` or `ANDROID_SDK_ROOT` in the environment you run `mm` from. mm refuses to create the workspace and tells you so if neither is set and the project has an untracked `local.properties`. `mm scan` and `mm resolve` run in the project directory, where `local.properties` is present.

Because the workspace is created fresh and deleted after every run, each `mm update` is a cold Gradle build with no reusable daemon or build cache. Allow for that when choosing test tasks. Gradle commands are given 900 seconds, and each configured test phase 600 seconds.

### What mm runs

| Purpose | Command |
| --- | --- |
| Discovery | `./gradlew versionCatalogUpdate --interactive --no-daemon --console=plain` |
| Application | `./gradlew versionCatalogApplyUpdates --no-daemon --console=plain` |
| Inventory + resolution | `./gradlew mmGradleReport --init-script <packaged script> -Pmm.reportDirectory=<report directory> --no-daemon --console=plain --rerun-tasks --no-build-cache` |
| Vulnerabilities | `trivy sbom --format json --scanners vuln <report directory>/bom.json` |

`mmGradleReport` is mm's own packaged task, added through an init script rather than a project plugin. It depends on `cyclonedxBom` for the inventory and additionally records, for every selected configuration, the resolved modules, variants and dependency edges Gradle's public resolution APIs report. mm reads both the inventory and this resolution report before removing its owned output, and every vulnerability finding is checked against a module the resolution actually selected.

Each Gradle command runs from the project root with a 900-second timeout, closed standard input and the project environment. mm strips `VIRTUAL_ENV` and inherits the remaining environment. mm owns one temporary path in the project, `gradle/libs.versions.updates.toml`, and removes it before tests, change detection or a commit; it reclaims a leftover report from an interrupted run only when its ownership marker is intact. The inventory, the resolution report and the packaged init script go to a fresh directory under `~/.mm` that mm passes to Gradle as `-Pmm.reportDirectory` and removes after each task. It rejects unmarked paths and symlinks and preserves their contents. It never touches your `build` directories.

### What mm changes

mm edits catalogue library and plugin versions through the update plugin. Every alias sharing a `version.ref` changes as one group, including mixed library/plugin groups. Independently versioned aliases remain separate targets. Each group gets one chosen candidate and one application per invocation; a failure does not try another version.

Simple literal versions and simple `version.ref` declarations are supported. Rich or ambiguous declarations remain blocked. A library without a catalogue version stays under platform or BOM control and never acquires a version. SDK, compileSdk/targetSdk, Gradle-wrapper, dependency-override and hard-coded declaration changes require manual preparation.

A direct security fix requires an exact advisory fix version, or one unambiguous version on the installed major/minor branch, followed by native Gradle validation. Transitive parent, BOM and plugin updates require an independently discovered catalogue proposal and unambiguous ownership in the covered resolution graph. An advisory links to a catalogue target only when every owner of it under that target is direct: an advisory reached through a parent, platform or plugin owner is withheld with that reason, and an advisory in a group whose discovery is blocked is withheld with the block's reason. Unsupported ownership remains visible as a prerequisite. An advisory with a published fix is completed when the catalogue target that owns it directly is applied and tested; the next `mm scan` reports anything still open. An advisory without a published fix is saved as blocked and never applied.

### Release-age policy

Known releases younger than `min_version_age_days` are withheld. For bun, uv and mvn, unknown or unavailable dates do not prevent updates, and `min_version_age_days = 0` skips their lookups. Gradle is fail-closed: a target is eligible only when every member's exact POM proves it at least `min_version_age_days` old, even at 0; an unknown date or failed lookup saves it as blocked with the reason. PyPI dates come from `pypi.org` with the exact package name and version checked, mvn and Gradle dates come from exact POMs, and those dates are cached under `~/.mm/publications` for 24 hours. npm dates come from `bun info` in the project and are looked up on every scan, because bun's registry configuration can change without mm noticing.

Set `gradle_repository_routing = "standard-public"` only when relevant public repositories have no credentials or custom content/exclusive routing. This declaration enables trusted publication lookups from Maven Central, Google Maven and Plugin Portal. Without the declaration every Gradle target is blocked with `Public repository routing has not been declared; automatic publication eligibility requires gradle_repository_routing = 'standard-public'`.

POM group and version fields may inherit literal values from a parent with complete coordinates. For mvn and Gradle alike, unresolved properties, ambiguous declarations, mismatched coordinates and non-UTF-8 POMs leave the publication date unknown.

`mm scan` prepares each Gradle target once: owner selection, native validation and publication age. `mm update` and `mm resolve` apply saved targets only, each through one `versionCatalogApplyUpdates`, then run the configured test phases; they never scan, rediscover, run `build_command` or push. Blocked findings stay visible and do not stop other updates from being promoted.

### Inventory coverage

The generated inventory must be CycloneDX JSON version 1.5 or later, with non-empty components and at least one Maven package URL. A missing, empty or malformed inventory is a scan error.

Vulnerability scanning covers the project configurations your CycloneDX configuration selects. The default covers resolvable project configurations, including test and tooling dependencies. Buildscript and plugin implementation dependencies require explicit CycloneDX configuration and are not implied by catalogue plugin-update support. A finding in the inventory is not by itself a claim about the shipped application.

### Known limitations

- Verified against Gradle 9.6.1 and JDK 21. Version Catalogue Update 1.1.1 uses an API deprecated for Gradle 10; Gradle 10 is not supported.
- When Version Catalogue Update 1.1.1 omits an update report, mm recognizes the no-update case from that release's exact log line. Other plugin versions may change this contract.
- CycloneDX and Trivy emit configuration-resolution and unsupported-hash warnings on this stack. Verify the generated inventory rather than relying on warnings or exit status alone; these warnings do not imply missing catalogue coordinates.
- A configured test phase that runs longer than 600 seconds is recorded as a failure of that phase. A cold workspace build plus a large unit-test suite can reach this limit. Split the phase or narrow the Gradle task if it does.
- Only `gradle/libs.versions.toml` is supported. Custom catalogue locations, dependency overrides and hard-coded versions in build scripts are out of scope.

## VCS workflow

Configured projects are expected to be colocated jj/Git repositories with an `origin` remote and a `main` bookmark. Git detached HEAD is normal under jj and is not treated as an error.

`mm update` uses the `mm/update-dependencies` bookmark and a temporary jj workspace under `~/.mm/workspaces/<project>`. Each eligible finding is applied, tested and committed there. A failed finding is discarded and retried by the next `mm update` against the same saved scan; passing ones are not reapplied. When no attempted finding is failing, the bookmark is promoted to local `main`; run `mm sync` to publish it. A successful `mm scan` replaces the saved findings and their pending statuses.

`mm resolve` takes over pending update work on `mm/resolve-dependencies` in the project directory, applies the next failed finding and stops at a failure with its changes in place. Commit the repair, then run `mm resolve PROJECT --continue` to test it without reapplying the update. When every finding passes, resolve promotes to local `main` like update.

In both flows, on bun, mvn and uv projects, a package command that changes no files fails the finding in `apply`. On Maven this is what a transitive-only package does. On Gradle, a catalogue target that is already applied still passes without a commit.

`mm sync` fetches and pushes the `main` bookmark directly. It does not switch branches or depend on Git checkout state.

## Requirements

* trivy, except for uv projects with `scan_secrets = false`
* jj
* Python 3.14
* JDK 21 and a project Gradle wrapper for `gradle` projects
* uv

## Supported Languages and Tools: 

* Java - `mvn`
* Python - `uv`
* Typescript / Javascript - `bun`
* Kotlin / Android - `gradle`

For bun, mm fixes and updates only packages the root `package.json` declares once, in `dependencies` or `devDependencies`, with a registry version range and no entry in `optionalDependencies`, `peerDependencies`, `overrides` or `resolutions`. Workspace members, nested copies, and `file:`, `link:`, `workspace:`, alias, Git and URL sources are reported without a fix.

## Contributing 

Put bluntly - I probably don't want your contribution. This is primarily a personal tool and I have no aspirations of trying to expand it to support every language, tool chain or use-case. You are encouraged to fork the project if you want to use tools I don't. I offer no guarantee of reading your issues or responding to your PRs. I do not wish to interact with your LLM agents or humans regurgitating LLM output. Please communicate in your own words or don't contact me at all.

### Development checks

Run the default test suite and each static check directly before submitting a
change. The default suite runs against real jj repositories, so it requires `jj`
0.45.1 and `git` on `PATH` (jj shells out to git for fetch and push). It needs no
network.

```sh
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run lint-imports
```

Repository functions are limited to a McCabe complexity of 10, six returns,
12 branches, and 50 statements. Process launches must go through
`maintenance_man.process`; that owner module and tests are exempt from the
direct-process import ban so the adapter can be implemented and test fixtures
can exercise subprocess boundaries. Parameter-count rule PLR0913 stays off
because the codebase preserves explicit dependency injection. TRY003, TRY004,
TRY300, and TRY301 stay off because they would change established exception
boundaries and message contracts. Ruff preview rules are disabled. Deptry is
deferred until dependency ownership policy is designed.

The real-Gradle producer test is separate from the default suite. It is
skipped unless `MM_GRADLE_WRAPPER` points to an executable `gradlew` whose
directory also contains `gradle/wrapper`. It needs JDK 21 and network access to
the Gradle plugin portal:

```sh
MM_GRADLE_WRAPPER=/path/to/project/gradlew uv run pytest tests/test_gradle_package.py -m integration -q
```
