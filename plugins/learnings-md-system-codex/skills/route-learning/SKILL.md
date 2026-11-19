---
name: route-learning
description: Route an existing lesson when a LEARNINGS search hit saved you, the user reports recurrence or asks to make a rule, hook, or skill, or a review closes a recurring root-cause class. Do not use for a first occurrence or an expected nonzero probe.
---

# Route a learning

Ask: who needs this lesson, and when? Pick one destination for the existing
lesson. Use the bundled [search-learnings](../search-learnings/SKILL.md)
skill to find the shared corpus and CLI when needed.

## First and second contact

First contact: fix the mistake, then add one archive line with
`learn add <topic> "<section>" "<root cause + what works>"`.

Codex has no automatic failure nudge from this plugin. Second contact is a
`learn search` hit that saved you or the user reporting recurrence, such as
"this keeps happening". Do not wait for a `Recorded before` message.
Identify the existing lesson and verify that it applies. A lexical match is
not proof of the same root cause; an unrelated suggestion is not second
contact. State why the lesson was missed or how it helped, then route it
instead of adding a duplicate archive entry.

## Choose a destination

| When the lesson is needed | Destination |
| --- | --- |
| A check can prevent the mistake | A hook or test |
| Every change in this repository must follow it | The repository's agent instructions, such as `AGENTS.md` or `CLAUDE.md` |
| A term needs one shared meaning | `CONTEXT.md` |
| A reversed design choice needs an explanation | A decision record under `docs/adr/` |
| The current state or next step changed | `PLAN.md` |
| A procedure applies to one kind of task | A repository skill in its configured skill directory |
| It remains a one-off | Leave it in the archive |
| The current model already handles it without the entry | Route nowhere and say why |

Try a hook or test before adding prose. A repository-wide instruction must
explain why a check cannot enforce it. Keep terms, design decisions, current
plans, and procedures in their separate destinations; do not repeat the
lesson across files. Follow the repository's existing documentation and
skill conventions rather than creating another store.

## Make and verify the change

1. Read the destination and its applicable repository instructions first.
   Follow its size or skill-count limits; remove superseded guidance before
   adding more at a limit.
2. Use the target host's supported guard interface for a hook. A Claude hook
   registration does not establish enforcement in Codex. Prove a guard on a
   known positive and a clean near-neighbor before shipping it.
3. Put a regression test beside the behavior it protects. Observe the bug
   before the fix and verify the corrected behavior afterward.
4. For a prose change, check the diff and relevant references. Remove any
   instruction that the new check replaces.
5. Follow the repository's branch, review, and landing rules for every
   change. This skill grants no additional publishing or merge permission.

Do not add a timer, queue, cross-repository pool, or duplicate corpus. If the
mistake was an expected probe or the existing entry adds no useful guidance,
route nowhere and state that decision in one line.
