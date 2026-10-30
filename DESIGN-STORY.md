# Design story: from collecting lessons to applying them

This began as an attempt to help coding agents carry useful lessons from one
session into the next. The project explored automatic capture, retrieval,
and maintenance before shifting toward a smaller workflow: record a mistake,
then put recurring lessons into the checks, instructions, or procedures that
guide later work.
The practical lesson was that recording a rule did not reliably stop the
same mistake. Recurring lessons needed to reach the agent at the next
decision, preferably through an enforced check.

The stages below overlap. Shared storage and support for two coding hosts
were lasting infrastructure improvements, alongside changes to how lessons
were collected and used. Later usage audits helped change that workflow;
they did not establish how often the system prevented a repeated mistake.

## 1. Capture and retrieval

Each repository had a `LEARNINGS.md` file. A script reviewed the conversation
every 10 turns, later 20, and also ran before context compaction (condensing
a long conversation) and at session end. It used a model to extract lessons
and write them into the archive.

A search command and a skill gave the coding agent a way to find those
lessons later. Reference counters recorded some retrieval activity. Useful,
specific observations could be captured, but that did not show whether an
agent would find and apply them when a similar problem came back.

## 2. Maintaining and sharing the archive

As the archive grew, more tools were added:

- **Validation** checked stored observations against later sessions.
- **Distillation** condensed each project's archive into a portable summary.
- **Cross-project mining** combined word-overlap matching and model calls
  to group related observations and write more general guidance.
- A **currency pass** looked for outdated or contradictory material.

These experiments produced useful engineering changes. Stable six-character
entry identifiers replaced matching entries by quoted text, which had made
updates fragile. Tests of repeated phrases across project summaries found
little overlap, prompting a different matching method.

They also added coordination and failure handling. One consolidation call
timed out after 300 seconds on a 125-entry file and was silently abandoned.
The resulting rule was that unfinished work needed an explicit outcome and
notice. Maintenance was becoming a substantial system of its own.

## 3. Shared storage and two hosts

Alongside the archive work, the project expanded to support Claude Code and
Codex. Executables and durable state moved out of one host's configuration
directory. A shared core handled corpus operations, while a thin adapter for
each host translated its events and context format.

The central store also kept archive changes out of project checkouts. This
was an infrastructure change, not a replacement learning strategy. Shared
storage and the host-adapter boundary remain part of the current system.

## 4. Managing growth

Maintenance expanded to include a cap of 1,000,000 bytes per archive,
mechanical and model-driven deletion, scheduled batches, and tiers for
different classes of material.

Growth was concentrated. A later audit of 50 archives found only two above
512 KB; the median archive was under 100 KB. Much of the machinery addressed
the difficult large cases.

Those cases exposed real costs. One archive remained at 106 percent of its
cap after three failed distillation batches. A lock defect prevented semantic
pruning from running. One maintenance batch took 4.5 hours and failed during
the merge.

## 5. Measuring recorded use and reducing capture

The next audit examined how much recorded retrieval accompanied all that
capture and maintenance:

| Measure across the archives | Value |
|---|---|
| Entries | 9,297 |
| Summed index reference counts | about 85 |
| This system's own repository: entries / index references | 1,559 / 24 |

There was no direct search counter yet. Index reference counts were a proxy,
not a complete record of reading, and they did not measure whether a lesson
changed later work. They were a warning signal about how much machinery had
been built without strong evidence of corresponding reuse.

The response was a quieter corpus. Scheduled capture and automatic
maintenance were retired. A few manual model-driven tools remained until
the next stage. Rather than reviewing every conversation for something to
save, the workflow focused on resolved mistakes.

The failure hook, a script run when a command fails, began looking for a
possible match in the archive and printing `Recorded before`. Statistics
tracked entries, searches, and repeats, although the search measurement
needed a later correction.

## 6. Routing recurring lessons

A second audit looked across the central store:

| Measure across the archives | Value |
|---|---|
| Entries | 10,550 |
| Recorded reads | 331 |
| Topic files with no recorded reads | 481 of 617 |

These are recorded-access measures. They should not be treated as a measured
change in total reading from the earlier index-only proxy.

The audit also examined the 15 observations pinned at the top of this
project's archive. Most were conventions, design rules, or tool procedures.
Many already existed as instructions elsewhere, yet the mistakes recurred.
The audit observed that enforced checks had been more effective at stopping
some recurrences: an observation, not a counted result.

The next change concerned where a recurring lesson belonged. A note could
remain useful as an archive entry, but a recurring problem might need a
test, a hook, an instruction, or a procedure available at the relevant task.

The current workflow is:

- **First contact:** fix the mistake and record one observation with
  `learn add`.
- **Second contact:** a possible-repeat nudge or a useful search result
  prompts the coding agent to ask, *who needs this lesson, and when?*
- **Route or decline:** the agent chooses one destination. Prefer a test or
  hook when a check can prevent the error. Use instructions or a skill for
  guidance that needs judgment. Keep a one-off in the archive, or decline a
  permanent rule when it would add no useful guidance.

The router is a skill the coding agent follows. It is not an autonomous
classifier or a background process that promotes notes into policy. Changes
go through the repository's review and approval process.

The remaining model-driven workers were removed. The supporting hooks and
CLI make no additional model calls; the coding agent still interprets the
lesson and decides what to change as part of its normal work.

## Engineering lessons from building it

The implementation had its own recurring mistakes. An internal retrospective
estimated roughly 90 review-fix rounds across 10 features by examining commit
history. Its classification put roughly 70 percent of those rounds into five
groups: shared-file coordination, covering every writer, marker timing,
validating model output, and units or path assumptions.

For example, one writer could take a lock while another writer of the same
file did not. A completion marker could be written at the wrong point and
permit duplicate work. Archive notes about these problems had not reliably
prevented them from passing the initial implementation and tests.

The response was a pre-flight checklist before opening a pull request, plus
an explicit threat model defining what the implementation and review must
protect against. This applied the same idea as the router: put guidance
where the next decision happens. The [README](README.md#the-pre-flight-gate)
describes the checklist in more detail.

## What survived

- One shared corpus and core, with adapters for Claude Code and Codex.
- Explicit capture and retrieval, without scheduled archive writers or
  additional model calls from the supporting tools.
- An agent-led procedure for turning recurring observations into checks,
  instructions, or skills, with normal review for the resulting changes.
- Stable identifiers for entries, and bounded instruction files that shed
  obsolete guidance instead of accumulating it indefinitely.
- Checks proven on both a known bad input and a known good control, with
  failure handling that makes incomplete work visible.

## Where it stands

The first reading after the router landed covered the 77 main-session
Claude Code transcripts the host still retained: a 30-day window, because
the planned earlier window was no longer available. It does not cover Codex
and is not a controlled before-and-after comparison.

| Signal | Sessions |
|---|---|
| Generic failure nudge shown | 43 |
| `Recorded before` nudge | 32 |
| Router skill loaded | 5, all after a `Recorded before` nudge |
| `learn search` run | 19 |
| `learn add` run | 21 |

Search did not disappear as expected. Whether repeat mistakes declined is
still unresolved. The repeat detector uses three shared tokens, so it can
name an unrelated entry. Usage-error false matches also inflated the counts
until they were silenced. The five recorded skill loads show some engagement
with the procedure; they do not count completed changes or prevented mistakes.

The next reading will help decide whether to replace the repeat match. A
`Recorded before` nudge that still names an unrelated entry is the signal
to replace it rather than tune it.
