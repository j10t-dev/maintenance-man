- Add `integration_strategy` option to `[projects.*.test]`: `"all"` (default, run integration after every update) vs `"final"` (run unit per-update, integration once at stack top after all updates processed). On final integration failure, don't fail the whole stack — leave it to the user to investigate/remove the offending branch
- show config command (filter?)
-  post update does not update history / scan findings [should re-run at  top of stack to confirm all resolve?]
- post update fail - there's no way to see which ones failed outside of scrolling up to output
- global TODO

