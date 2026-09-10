Shared workflows — public repositories
======================================

The two pull-request security gates, in a repository public enough to run
against public repositories.

Why this exists
---------------

A required workflow has to live in a repository **at least as visible as the
one it gates**. GitHub refuses otherwise, because running a less visible
workflow against a more visible repository would expose the workflow's contents
in public logs:

````
Workflows cannot be required from a less visible repository
````

`catch-internal/shared-workflows` is **internal**. The public repositories in
`catch-oss` are **public**. So the enterprise rulesets sourced from the internal
repository could never run against them: no check run is created at all, and
the required check can neither pass nor fail. It just never arrives, and every
pull request on a public repository sits blocked behind it.

This repository is public, so it can. The visibility rule is one-directional —
public is the most visible — so workflows here would also satisfy private and
internal targets. They are not used that way: the internal repository keeps the
private exception register, and that is the whole reason the two are separate.

What is here
------------

````
.github/workflows/
  dependency-vulnerability-gate.yml   Required workflow: HIGH and CRITICAL dependency vulnerabilities
  eol-component-gate.yml              Required workflow: end-of-life components

.github/actions/
  security-policy/                    Renders the exception register into scanner config
  eol-scan/                           Grades declared runtime versions against endoflife.date

.github/rulesets/
  *.json                              Enterprise ruleset definitions targeting catch-oss
````

What is deliberately **not** here: the Asana support-board sync, the scheduled
security report, the enterprise secret sync, the org application scripts, and
the private exception register. Those stay in
`catch-internal/shared-workflows`, which remains the home for everything
touching the private estate.

The exception register
----------------------

`.github/actions/security-policy/exceptions.yml` starts empty, and the file
itself carries the full rules. The one that matters:

> **Public repositories only.** Never add an entry for a private or internal
> repository — that belongs in `catch-internal/shared-workflows`. An exception
> states that a named repository is knowingly running a named unpatched
> vulnerability, and this repository is world readable.

For a public repository that is not a disclosure: the code, the dependency tree
and the advisory are all public already, and anyone can reproduce the finding
by running the scanner. That asymmetry is what makes two registers the right
shape rather than an annoyance.

An empty register is not a gap. Both gates render it into an explicit scanner
configuration either way, and passing that configuration is what stops a target
repository supplying its own `.grype.yaml` to weaken the gate from inside the
pull request being gated.

Keeping this in step with the internal repository
-------------------------------------------------

The two gate workflows and the two composite actions here are **copies**. They
have to be: a public workflow cannot fetch a composite action out of an
internal repository, for the same visibility reason this repository exists.

So they can drift, and drift here is silent — a fix made internally does not
reach public repositories, and the reverse. When changing a gate or an action,
change it in both. Worth adding a scheduled job that diffs the shared paths and
raises an issue when they diverge; until then it is a review habit.

Applying the rulesets
---------------------

The definitions in `.github/rulesets/` target the `catch-oss` organisation
only, and reference the workflow files in **this** repository. The
enterprise-wide rulesets sourced from `catch-internal/shared-workflows` should
exclude `catch-oss` at the same time, or public repositories end up with both
the working check and the broken one.

````bash
scripts/apply-rulesets.sh
````

`repository_id` is left as `0` in the committed JSON deliberately. A numeric
repository id is meaningless to read and easy to leave stale, so the script
resolves it from the repository name and injects it at apply time.

Both are created in **evaluate** mode deliberately. Promote one by editing
`enforcement` to `active` and applying it to the id the create call returned:

````bash
scripts/apply-rulesets.sh eol-component-gate <id>
````

Do not target every branch. Required workflows run in the pull-request and
merge-queue lifecycle, and targeting all branches would block direct branch
creation.

The end-of-life gate is the one likely to light up first — most repositories
have something old pinned somewhere. Run it in evaluate mode for a cycle and
clear the backlog before making it blocking.

Repository access
-----------------

Nothing to grant. The gates call composite actions from this repository, and a
public repository is readable by any workflow, so the
**Settings → Actions → General → Access** grant that the internal repository
needs does not apply here.

Action refs
-----------

The gates call their actions at `@main`, the same ref the rulesets use for the
workflow files, so a workflow and the actions it calls cannot drift apart. The
consequence is that a change under `.github/actions/` reaches every gated
public repository the moment it merges. There is no soak period, and rolling
one back means reverting on `main`. Review changes there on that basis.
