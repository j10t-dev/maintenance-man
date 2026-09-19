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

```bash
➜  maintenance-man git:(main) ✗ mm --help
Usage: mm COMMAND

Config-driven CLI for routine software project maintenance.

╭─ Commands ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ build           Build a project's artefacts.                                                                                                   │
│ deploy          Deploy a project.                                                                                                              │
│ list            List all configured projects with scan findings summary.                                                                       │
│ scan            Scan projects for vulnerabilities and available updates.                                                                       │
│ test            Run a project's test suite.                                                                                                    │
│ update          Apply updates from scan results to a project.                                                                                  │
│ --help (-h)     Display this message and exit.                                                                                                 │
│ --version (-v)  Display application version.                                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

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

The following defaults can be globally configured: 

```toml
[defaults]
min_version_age_days = 7 # how old dependencies should be before trivy reports the update, guards against package takeover attacks.
healthcheck_url = "http://healthchecker:8080" # the URL of your healthchecker service (if using)
```

## Gradle projects

`package_manager = "gradle"` targets a project that uses a Gradle wrapper and a version catalogue at `gradle/libs.versions.toml`. mm runs the project's own `./gradlew`. The project must supply its Gradle wrapper and build scripts; mm does not install plugins or change that setup.

### Required project setup

The project must apply these two plugins, pinned to these versions, in its root build script:

```kotlin
import org.cyclonedx.gradle.CyclonedxDirectTask
import org.gradle.api.file.RegularFile

plugins {
    id("nl.littlerobots.version-catalog-update") version "1.1.1"
    id("org.cyclonedx.bom") version "3.4.1"
    // Retain the project's existing plugins.
}

allprojects {
    tasks.named<CyclonedxDirectTask>("cyclonedxDirectBom") {
        val relative = if (project.path == ":") "root" else
            "projects/" + project.path.removePrefix(":").replace(':', '/')
        jsonOutput = rootProject.layout.projectDirectory.file(
            ".mm-gradle-inventory/direct/$relative.json"
        )
        xmlOutput.convention(null as RegularFile?)
    }
}
tasks.cyclonedxBom {
    jsonOutput = layout.projectDirectory.file(".mm-gradle-inventory/bom.json")
    xmlOutput.convention(null as RegularFile?)
}
```

Configure the test commands as for any other project, for example `test_unit = "./gradlew :app:testDebugUnitTest"`.

Standard generated build and cache outputs must already be ignored by the repository; mm verifies that its dependency commits contain no generated reports.

Export the Android SDK location before running `mm update`. `mm update` applies changes inside a throwaway jj workspace under `~/.mm/workspaces/`, and a jj workspace checks out tracked files only. `local.properties` is conventionally untracked, so `sdk.dir` is not available there and an Android build cannot find the SDK. Export `ANDROID_HOME` or `ANDROID_SDK_ROOT` in the environment you run `mm` from. mm refuses to create the workspace and tells you so if neither is set and the project relies on `local.properties`. `mm scan` and `mm resolve` run in the project directory, where `local.properties` is present.

Because the workspace is created fresh and deleted after every run, each `mm update` is a cold Gradle build with no reusable daemon or build cache. Allow for that when choosing test tasks. Gradle commands are given 900 seconds, and each configured test phase 600 seconds.

### What mm runs

| Purpose | Command |
| --- | --- |
| Discovery | `./gradlew versionCatalogUpdate --interactive --no-daemon --console=plain` |
| Application | `./gradlew versionCatalogApplyUpdates --no-daemon --console=plain` |
| Inventory + resolution | `./gradlew mmGradleReport --init-script <packaged script> --no-daemon --console=plain --rerun-tasks --no-build-cache` |
| Vulnerabilities | `trivy sbom --format json --scanners vuln .mm-gradle-inventory/bom.json` |

`mmGradleReport` is mm's own packaged task, added through an init script rather than a project plugin. It depends on `cyclonedxBom` for the inventory and additionally records, for every selected configuration, the resolved modules, variants and dependency edges Gradle's public resolution APIs report. mm reads both the inventory and this resolution report before removing its owned output, and every vulnerability finding is checked against a module the resolution actually selected.

Each Gradle command runs from the project root with a 900-second timeout, closed standard input and the project environment. mm strips `VIRTUAL_ENV` and inherits the remaining environment. mm owns exactly two temporary paths, `gradle/libs.versions.updates.toml` and `.mm-gradle-inventory/`, and removes both before tests, change detection or a commit. mm reclaims leftovers from interrupted runs only when their ownership markers are intact. It rejects unmarked paths and symlinks and preserves their contents. It never touches your `build` directories.

### What mm changes

mm edits catalogue versions only, through the update plugin:

- Every alias sharing a `version.ref`, including libraries and plugins together, is upgraded in one attempt, tested once and produces at most one dependency-update commit across vulnerability and ordinary-update findings. Mixed groups use vulnerability priority and a vulnerability-labelled commit. Independently versioned aliases remain separate targets even when their coordinates match.
- Supported declarations are simple literal versions and simple `version.ref` declarations. Rich versions, constraints and ambiguous mappings are reported as blocked, never flattened.
- A library with no catalogue version stays under platform or BOM control and never acquires a version.
- Vulnerability fixes are applied automatically only when a catalogue library owns the coordinate and the advisory names a single exact fix version. Transitive-only findings, BOM-owned children, plugin implementation dependencies, ranges and multiple alternative fixes are reported for manual resolution; mm never assumes that upgrading a parent or plugin fixes a transitive advisory.

### Release-age policy is stricter for Gradle

mm checks Maven Central for the publication timestamp of every artifact a change touches. It uses the real coordinate for libraries and the `<id>:<id>.gradle.plugin` marker for plugins. If any one of them has no verifiable timestamp, the whole group is blocked, including vulnerability fixes. Setting `min_version_age_days = 0` removes the waiting period; it does not accept unknown publication dates.

Artifacts published only to Google Maven or the Gradle Plugin Portal usually have no Maven Central timestamp, so mm will report those updates and refuse to apply them automatically. Apply those by hand. Network and lookup failures also block changes. HTTP `Last-Modified` headers and first-observation times are not publication dates. mm rechecks the catalogue target, catalogue state and publication evidence before every automatic change, including findings loaded from older scan files.

`mm resolve` follows the same safety rules. `--continue` validates the catalogue, relationships and current publication evidence before tests or READY promotion; passing tests cannot make a blocked group ready. An update with any remaining blocked group exits with code 4 and cannot finalise, promote or submit changes. Eligible groups in a mixed run can still be applied, with accepted changes left on the maintenance bookmark. A fully blocked run creates no workspace and runs no tests or commits.

### Automatic publication eligibility requires a routing declaration

Gradle automatic updates require an explicit project declaration:

```toml
[projects.example]
path = "/path/to/project"
package_manager = "gradle"
gradle_repository_routing = "standard-public"
```

Set `gradle_repository_routing` only when the recognized public repository roots relevant to this project's library and plugin candidates use standard Maven routing without credentials, content filters or exclusive-content rules affecting those roots. This includes settings, subprojects and plugin-management repositories. Revisit the declaration when repository configuration changes. A credentialed public root, a content filter restricting that root, or an exclusive-content rule affecting it prevents this declaration. mm relies on the operator's assertion; it does not detect these settings.

Omit the field for unsupported or unknown routing. Inventory, scanning and candidate reporting remain available, while automatic candidate groups are withheld with an age prerequisite. A zero minimum age does not bypass this prerequisite. The declaration does not make custom repository URLs trusted, expand configured project/domain scope, or replace native candidate and exact-artifact publication checks.

Private Trivy database caches are released after a run completes or replacement evidence is durably saved. The ledger retains the recorded snapshots and receipts. Unfinished runs keep the cache needed for recovery.

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

Configured projects are expected to be colocated jj/Git repositories with a GitHub `origin` remote and a `main` bookmark. Git detached HEAD is normal under jj and is not treated as an error.

`mm update` uses the `mm/update-dependencies` bookmark and a temporary jj workspace under `~/.mm/workspaces/<project>`. Passing findings are committed and the bookmark is promoted to `main` locally; run `mm sync` to publish `main`.

`mm resolve` uses the `mm/resolve-dependencies` bookmark for manual fixes. When the findings are ready, the bookmark is pushed and a GitHub PR is opened from that bookmark.

`mm sync` fetches and pushes the `main` bookmark directly. It does not switch branches or depend on Git checkout state.

## Requirements

* trivy
* jj
* gh
* Python 3.14
* JDK 21 and a project Gradle wrapper for `gradle` projects
* uv

## Supported Languages and Tools: 

* Java - `mvn`
* Python - `uv`
* Typescript / Javascript - `bun`
* Kotlin / Android - `gradle`

## Contributing 

Put bluntly - I probably don't want your contribution. This is primarily a personal tool and I have no aspirations of trying to expand it to support every language, tool chain or use-case. You are encouraged to fork the project if you want to use tools I don't. I offer no guarantee of reading your issues or responding to your PRs. I do not wish to interact with your LLM agents or humans regurgitating LLM output. Please communicate in your own words or don't contact me at all.
