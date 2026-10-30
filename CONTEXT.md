# Learning lifecycle glossary

The Claude Code and Codex adapters use the same corpus and state model.

| Term | Meaning |
|---|---|
| Host | The coding-agent environment that emits lifecycle events, such as Claude Code or Codex. |
| Host adapter | Code that translates one host's events and context format into the shared workflow. |
| Project identity | The stable identity of a project across its clones and linked worktrees. A checkout path is evidence of location, not the identity itself. |
| Project corpus | The project's archive of observations recorded with `learn add`. |
| Entry | One observation in the archive, addressed by a stable identifier. |
| Routing | Moving a recurring lesson into the test, hook, instruction, or skill where it can guide the next relevant action. |
| Neutral state | Durable machine-local state shared by the host adapters. |
| Legacy state | State retained from an older installation. Deployment does not silently reinterpret it as a new installation. |
| Activation | The record that selects a valid neutral-state generation. |
| Projection | A replaceable representation of corpus contents in a checkout. The authoritative external corpus remains separate. |

See [the design story](DESIGN-STORY.md) for how the system reached this
model, and [runtime artifacts](docs/ARTIFACTS.md) for its files on disk.
