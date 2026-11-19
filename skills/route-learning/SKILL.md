---
name: route-learning
description: Decide where a lesson belongs after a resolved mistake or a tricky operation, instead of appending it to LEARNINGS. Use when the failure hook prints "Recorded before" (second contact with the same mistake), when a LEARNINGS search turns up an entry that saved you, when the user says "this keeps happening", "make this a rule", "add a hook for that", "turn this into a skill", or "where should this go", and when a review-fix round closes a recurring root-cause class. Do NOT use for the first occurrence of a failure (that is one `learn add` line to the archive) or for a probe that exited non-zero on purpose.
---

# Route a learning

A lesson goes where it will be read. Ask one question: **who needs this, and
when?** The answer names the destination. Pick exactly one.

| Answer | Destination | Cap |
|---|---|---|
| Nobody should need to remember it; a check can make it impossible | A hook or a test | Reviewed code, proven on a known positive and a known negative |
| Every session, before any change in this repo | The repo's agent instructions file (`CLAUDE.md` or `AGENTS.md`) | A size cap the repo chooses; enforce it with a test if you can |
| Anyone who has to name the thing; a term was used two ways | A glossary, if the repo keeps one (for example `CONTEXT.md`) | One row per term |
| Anyone who would otherwise undo a design choice already reversed | A decision record, if the repo keeps them (for example `docs/adr/`) | One record per decision |
| Anyone arriving next; the repo's state or next step changed | A plan or status file, if the repo keeps one (for example `PLAN.md`) | Current state only; no history |
| Anyone doing one kind of task here | A repo skill, `.claude/skills/<name>/SKILL.md` | Count per repo; one trigger each |
| Nobody yet; it was a one-off | Leave it in the LEARNINGS archive | None |
| Nobody; the current model would not make this mistake without the entry | Nothing. Say so in one line. | |

Skip a row whose file the repo does not have. Create one only if the user
asks for it.

## Rules

1. **Enforcement first.** Try the hook or test row before any prose row. A
   line routed to the instructions file carries one clause saying why it
   cannot be a check.
2. **The prose rows are not interchangeable.** The instructions file holds a
   rule every change must follow. A term goes to the glossary, a reversed
   choice to a decision record, a change of state to the plan, and none of
   those is repeated in the instructions file.
3. **Every write is a repo change.** Edit the file on a branch; it lands
   through the repo's normal review. In an unattended session, write the
   diff and stop; a person merges.
4. **At the cap, remove before you add.** The removal goes in the same change.
5. **Subtract.** While you are in the file, delete a rule that now has an
   enforcement, or a skill nothing has loaded in a month.
6. **No new stores.** No timer, no queue file, no cross-repo pool. If one
   seems necessary, the cap on the destination is wrong.

## Second contact, not first

First contact: fix it, then one archive line with
`learn add <topic> "<section>" "<root cause + what works>"`. Stop there.

Second contact is the failure hook printing `Recorded before: … [id]`, or a
`learn search` hit that saved you. That is when this skill runs. Say in one
line why the archive line was not applied, then route. First verify that the
cited lesson applies: the failure hook supplies a lexical cue, not proof of
the same root cause. An unrelated suggestion is not second contact.

## How to write each destination

**Hook or test.** A test goes beside the code it guards, in the repo's test
suite. A guard on agent behavior goes in a PreToolUse hook registered in the
host's settings (for Claude Code, `~/.claude/settings.json`), with a test of
its own. Before it ships, watch it fire on the input it must catch and stay
quiet on a clean near-neighbor. A hook that only warns is prose with extra
steps; block or do not bother.

**Instructions-file line.** One sentence, in the section it belongs to, with
the "why not a check" clause. If the file has a size cap, check it first;
near the cap, remove a line that has since gained an enforcement.

**Glossary row.** The term, what it means in this repo, and the words to
avoid for it. Write the row when a term was coined or when a review showed
two people meant different things by it.

**Decision record.** One record, added to the records index if there is
one: the choice, what was tried before, and why it was reversed. Write one
only for a decision someone would otherwise make again.

**Plan.** Replace the current state and the next step. The file holds one
state, not a history.

**Repo skill.** Frontmatter `name` and a `description` written as the
trigger: the task names, the phrases a user would say, and what it is not
for. Body under 6 KB: the procedure, the checks, the identifiers verbatim.
One skill per task kind; extend an existing skill before adding another.

**Archive.** Already there from first contact. Nothing to do.

## Decline

If the entry restates something the current model does unprompted, or the
mistake was a probe, route nowhere and say why. Silence is not decline; the
one line is.
