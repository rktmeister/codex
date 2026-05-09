# Upstream Merge Runbook

Use this when you need to fetch `upstream` and merge `upstream/main` into the
current branch while preserving local work.

Run all commands from the repository root unless noted.

## Ground Rules

- Do not push unless explicitly requested.
- Do not reset, clean, restore, or delete files to make the merge easier.
- Treat untracked and modified files as user or other-agent work.
- Prefer upstream's current structure, names, and APIs, while keeping local
  behavior and additions unless they are truly superseded.
- Resolve conflicts deliberately. Do not blindly take `--ours` or `--theirs`.

## 1. Inspect Local State

```sh
git status -sb
git remote -v
git branch --show-current
git rev-parse --abbrev-ref --symbolic-full-name @{u}
```

If there are tracked local changes, inspect them before merging:

```sh
git --no-pager diff --stat
git --no-pager diff --name-only
```

Untracked files can stay in place unless upstream now tracks the same paths.
For known untracked files, check for collisions after fetching:

```sh
git ls-tree -r --name-only upstream/main -- path/to/file another/file
```

## 2. Fetch Upstream

```sh
git fetch upstream
```

Then inspect divergence:

```sh
git rev-list --left-right --count HEAD...upstream/main
git log --oneline --left-right --cherry-pick --max-count=40 HEAD...upstream/main
```

The first command prints `<local-only> <upstream-only>`.

## 3. Merge

```sh
git merge --no-edit upstream/main
```

If the merge completes, skip to validation. If it stops with conflicts, continue
with the conflict workflow below.

## 4. Resolve Conflicts

List unresolved files:

```sh
git diff --name-only --diff-filter=U
```

For each conflicted file, inspect all sides:

```sh
git show :1:path/to/file   # base
git show :2:path/to/file   # ours, local branch
git show :3:path/to/file   # theirs, upstream/main
```

When resolving:

- Keep local additions and intentional behavior.
- Adapt local changes to upstream's current module boundaries and API shape.
- Keep upstream fixes, renames, generated-file layout, and new conventions.
- If both sides added tests, keep both sets unless they now assert duplicate
  behavior.
- After resolving one conflict pattern, search nearby for similar patterns with
  `rg`.

Remove conflict markers, then stage only the files you resolved:

```sh
git add path/to/file
git diff --name-only --diff-filter=U
```

The second command must print nothing before committing.

## 5. Format And Validate

For Rust changes under `codex-rs`, run:

```sh
cd codex-rs
just fmt
cargo test -p <changed-crate>
cd ..
```

If the merge changed `codex-rs/core`, shared protocol/config crates, or other
common surfaces, consider the broader relevant test suite. Ask before running a
full workspace test if it will be expensive.

Always run whitespace/conflict checks before finishing:

```sh
git diff --check
git diff --cached --check
git diff --name-only --diff-filter=U
```

## 6. Complete The Merge Commit

If Git stopped for conflicts, finish the merge after staging resolutions:

```sh
git commit --no-edit
```

If the merge already auto-committed, do not create another commit.

## 7. Final Checks

```sh
git status -sb
git rev-list --left-right --count HEAD...upstream/main
git log -1 --oneline --parents
```

Expected result after a successful merge:

- `git diff --name-only --diff-filter=U` prints nothing.
- `HEAD...upstream/main` reports `0` upstream-only commits.
- The latest commit is either the merge commit or the existing auto-merged head.
- Existing unrelated untracked files are still present and untouched.

