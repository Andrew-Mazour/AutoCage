# Scheduled documentation maintenance

This optional GitHub Actions workflow proposes only unambiguous case-correction fixes for relative Markdown links in the repository's allowlisted user documentation. It does not use an AI service, create timestamps or release notes, reformat whole files, or invent work. If fewer than three distinct broken-link repairs are available, it does nothing.

## What it changes

Eligible files are README.md, CHANGELOG.md, SECURITY.md, Markdown files under docs/, the Inspect integration README, and the BYO-repository example README. A link is eligible only when its relative target is missing due to letter casing, each path component has exactly one case-insensitive match, and resolving the corrected target stays inside the repository without following symlinks. External links, ambiguous matches, code examples, path escapes, other file types, and security/runtime/evidence code are out of scope.

The script deterministically chooses between three and ten eligible link repairs from a date-derived seed. The count and selected changes are reproducible for a given repository revision and date. The deterministic selection is pseudo-random sampling; it is not a source of new maintenance work.

## Dry run

After this workflow has been merged and enabled, a manual GitHub Actions run defaults to read-only dry-run mode. That scan job has contents:read permission only and cannot push a branch or create a pull request. It reports the candidate list and exits without modifying the checkout.

A local dry run is also available:

    python3 scripts/maintenance_docs.py --dry-run

The local script defaults to dry-run. The optional --apply flag changes only selected documentation files in the current checkout; it never commits or pushes.

## Schedule and review

The workflow is scheduled at 02:17, 08:17, 14:17, and 20:17 UTC. A date-derived hash selects one of those four slots. GitHub Actions scheduled runs are best-effort: queue load can delay a run, and a scheduled event can be delayed or dropped. If a run arrives outside its selected UTC hour, it skips rather than running at an unexpected time. The workflow also supports manual dry runs.

When enough justified changes exist, the workflow validates the complete documentation-link checker, script tests, its path allowlist, and git diff whitespace. It then creates a bot-attributed branch and pull request against main. It never pushes to main. Only one open PR with the automation branch prefix is allowed, and an existing date branch is never overwritten. A maintainer must review and merge the PR.

The proposing job is limited to schedule events or an explicit manual run on main. It does not run on pull_request events or execute pull-request code with write credentials. The scan uses read-only permissions; only the guarded proposal job has contents:write and pull-requests:write. It uses GitHub's built-in token and a pinned checkout action.

GitHub does not normally start a second workflow in response to a branch push or pull request created with GITHUB_TOKEN. The maintenance workflow therefore runs its own narrow validations before opening the PR. Reviewers can request or run the normal CI checks on the proposed branch as needed.

## Enable, pause, or disable

The workflow is not active until its separate PR is reviewed and merged. After merge, ensure scheduled workflows are enabled in repository Actions settings. To pause it, disable the workflow from the GitHub Actions workflow menu. To permanently remove it, merge a reviewed change deleting this workflow and script. Manual dry runs remain read-only and can be run before enabling the schedule.

The workflow is intentionally conservative. Most days should produce no PR because the repository has no eligible broken-link casing repairs.
