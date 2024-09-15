#!/bin/sh

set -eux

if git worktree add reviews refs/notes/devtools/reviews; then
  ( cd reviews; echo 'ref: refs/notes/devtools/reviews' > "`git rev-parse --git-dir`/HEAD" )
fi
if git worktree add discuss refs/notes/devtools/discuss; then
  ( cd discuss; echo 'ref: refs/notes/devtools/discuss' > "`git rev-parse --git-dir`/HEAD" )
fi
if git worktree add archives refs/devtools/archives/reviews; then
  ( cd archives; echo 'ref: refs/devtools/archives/reviews' > "`git rev-parse --git-dir`/HEAD" )
fi

git config --local author.email "🐶"
git config --local committer.email "🐶"
git config --local user.email "🐶"
git config --local --add notes.rewriteRef refs/notes/devtools/reviews
git config --local --add notes.rewriteRef refs/notes/devtools/discuss

worktrees=(
  1-introduction-base
  1-introduction
  2-numbers-in-detail-base
  2-numbers-in-detail
  3-going-forth-base
  3-going-forth
)

for worktree in "${worktrees[@]}"; do
  git worktree add "$worktree" "$worktree"
done
