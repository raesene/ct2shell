#!/usr/bin/env bash
# Publish the monitor's results to the GitHub repo as data/data.json.
# Run by ct2shell-publish.timer. Commits only when the records change, or
# when the existing file is older than the heartbeat, so the site can show
# whether the monitor is still alive.
set -euo pipefail

LIVE="${CT2SHELL_LIVE:-$HOME/ct2shell/live}"
CLONE="${CT2SHELL_CLONE:-$HOME/ct2shell/publish}"
REMOTE="${CT2SHELL_REMOTE:-git@github.com:raesene/ct2shell.git}"
BRANCH="${CT2SHELL_BRANCH:-main}"
KEY="${CT2SHELL_DEPLOY_KEY:-$HOME/.ssh/ct2shell_deploy}"
EXPORT="${CT2SHELL_EXPORT:-$HOME/ct2shell/ct2export}"

export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
export GIT_AUTHOR_NAME="ct2shell publisher" GIT_AUTHOR_EMAIL="ct2shell-publisher@users.noreply.github.com"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"

if [ ! -d "$CLONE/.git" ]; then
  git clone --quiet --depth 20 --branch "$BRANCH" "$REMOTE" "$CLONE"
fi
cd "$CLONE"

for attempt in 1 2 3; do
  git fetch --quiet origin "$BRANCH"
  git reset --quiet --hard "origin/$BRANCH"   # this clone only ever writes data/
  mkdir -p data
  "$EXPORT" -matches "$LIVE/matches.jsonl" -state "$LIVE/state.json" -out data/data.json
  if git diff --quiet -- data/data.json && git ls-files --error-unmatch data/data.json >/dev/null 2>&1; then
    echo "no change to publish"
    exit 0
  fi
  n=$(grep -c '"domain"' data/data.json || true)
  git add data/data.json
  git commit --quiet -m "data: $n domains ($(date -u +%Y-%m-%dT%H:%MZ))"
  if git push --quiet origin "HEAD:$BRANCH"; then
    echo "published $n domains"
    exit 0
  fi
  echo "push rejected (attempt $attempt); retrying on latest $BRANCH" >&2
  sleep $((attempt * 5))
done
exit 1
