# Maintenance Man (mm)

Maintenance Man(ager) is a CLI helper that makes the routine maintenance of your personal projects simpler.

## What

`mm` is a CLI tool that assists in the maintenance of configured projects. It supports the following core workflow: 

1. Scan project(s) for vulnerabilities, dependency updates and exposed secrets (via)
2. Update dependencies, validate via the target project's unit/integration/component tests.
  a. Each passing dependency update gets its own commit and branch. 
  b. All passing updates are batched into a single graphite-stack.
3. Build the deploy artifacts for the updated project(s) (if relevant)
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
package_manager = "uv" # required (one of: mvn, uv, bun), which package manager does the project use 
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

## Requirements

* trivy
* Python 3.14
* uv

## Supported Languages and Tools: 

* Java - `mvn`
* Python - `uv`
* Typescript / Javascript - `bun`

## Contributing 

Put bluntly - I probably don't want your contribution. This is primarily a personal tool and I have no aspirations of trying to expand it to support every language, tool chain or use-case. You are encouraged to fork the project if you want to use tools I don't. I offer no guarantee of reading your issues or responding to your PRs. I do not wish to interact with your LLM agents or humans regurgitating LLM output. Please communicate in your own words or don't contact me at all.
