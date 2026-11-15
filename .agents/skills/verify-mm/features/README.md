# Maintenance Man verification map

Use [verify-mm](../SKILL.md) for launch, doctor, evidence and cleanup. Each run owns one project called `fixture`, one isolated MM_HOME, two local wheel versions, a saved update and a bare local origin. Every fixture command runs through the helper; normal user configuration is never a precondition.

The helper's `drive` command proves the selected recipe using actual processes, picker input and VCS/persistence observations. Launch once per journey. Evidence uses feature-specific terminal filenames and named state snapshots. A mapped entry point is not proved merely because another entry point reaches similar code.

| Feature | Helper coverage | Other mapped entry points |
| --- | --- | --- |
| [Initialise and inspect projects](overview.md) | `mm init`, version and piped `mm list --detail` | Overview, aliases and TODO output are unproved by these recipes. |
| [Interactive dependency updates](update.md) | Invalid selection, cancel, numbered selection, uv application, tests and promotion; `--journey noop`: an apply that changes no files fails in `apply` | Batch, exclusions, keyword/default selection and other package managers are unproved. |
| [Sync main with origin](sync.md) | Single-project local bare-origin push, independently fetched | Multi-project, all-project, incoming/divergent history and unavailable origin are unproved. |
| [Recover a failed update](recovery.md) | `--journey recovery`: failed update, resolve pause, committed repair, continue and promotion | Other failed phases, missing bookmark, conflicts and multiple findings are unproved. |

The seed scan contains one synthetic available update and no advisories, secrets or blocked findings. Standalone `mm test`, live `mm scan`, vulnerability/release-age policy, Gradle/Android setup, build, deployment and healthchecks need separate disposable boundary fixtures. They are outside this initial map and must not be claimed from the update proof. Never weaken a missing precondition into a successful result.
