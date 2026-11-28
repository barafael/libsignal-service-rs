#!/usr/bin/env bash
# Builds langis/integration of barafael/libsignal-service-rs: upstream main, each branch below
# merged into it in order, and this script on top. Run it in any clone of libsignal-service-rs:
#
#   ./integration.sh        build the branch and print what it is
#   ./integration.sh push   build it, tag the old tip integration/<date>-<commit>, push both
#
# Where a branch conflicts with those before it, or needs more than a merge to build with them,
# the fork keeps the merge as done by hand in merge/<branch>: its first parent is the branch
# built so far, its second the branch. The script takes its tree while both still hold, and
# stops when one doesn't: then merge the branch by hand again, onto what the script printed,
# and push that as merge/<branch>. The script never resolves a conflict itself. Edit the list
# here, on the branch; once a pull request has landed, delete its line.
set -euo pipefail

UPSTREAM=https://github.com/whisperfish/libsignal-service-rs.git
FORK=https://github.com/barafael/libsignal-service-rs.git
PUSH=https://github.com/barafael/libsignal-service-rs.git
BRANCH=langis/integration

TOPICS=(
    fix/sync-to-self-once       # #476
    pr/sync-message-send        # follow-up to #476
    fix/keepalive-after-stall   # #481
    pr/custom-servers           # no pull request: servers of one's own
    fix/websocket-error-cause   # #482, stacked on #481
    pr/session-lock             # #488
    fix/stale-connections       # #490
    pr/story-flag               # #493
    pr/accept-language          # #495
    pr/signed-group-change      # #496
    pr/group-logs               # #497
    pr/sender-key-send          # no pull request yet: a group message in one request
    pr/story-list-send          # no pull request yet, on pr/sender-key-send: a story to a list
    fix/sealed-plaintext        # no pull request
    fix/ack-handle-drop         # #489, merged into rubdos' auto-ack (#442), not into main
)

script=$(git hash-object -w "$0")

# SKIP_FETCH=1 builds from the refs/integration/* already here, to try resolutions before pushing.
old=
if [ -z "${SKIP_FETCH:-}" ]; then
    git fetch -q --no-tags "$UPSTREAM" +refs/heads/main:refs/integration/main
    git fetch -q --no-tags "$FORK" "${TOPICS[@]/*/+refs/heads/&:refs/integration/&}"
    git for-each-ref --format='delete %(refname)' 'refs/integration/merge/' | git update-ref --stdin
    git fetch -q --no-tags "$FORK" '+refs/heads/merge/*:refs/integration/merge/*'
    old=$(git ls-remote "$FORK" "refs/heads/$BRANCH" | cut -f1)
    [ -z "$old" ] || git fetch -q --no-tags "$FORK" "+refs/heads/$BRANCH:refs/integration/old"
fi

tip=$(git rev-parse refs/integration/main)
for topic in "${TOPICS[@]}"; do
    resolved=refs/integration/merge/$topic
    if git rev-parse -q --verify "$resolved" >/dev/null; then
        if [ "$(git rev-parse "$resolved^1^{tree}")" != "$(git rev-parse "$tip^{tree}")" ] ||
            [ "$(git rev-parse "$resolved^2")" != "$(git rev-parse "refs/integration/$topic")" ]; then
            echo "merge/$topic is stale: merge $topic by hand onto $tip and push it as merge/$topic." >&2
            exit 1
        fi
        tree=$(git rev-parse "$resolved^{tree}")
    elif ! tree=$(git -c core.attributesFile=/dev/null merge-tree --write-tree --name-only "$tip" "refs/integration/$topic"); then
        echo "$topic does not merge (files below): merge it by hand onto $tip, push that as merge/$topic." >&2
        echo "$tree" | sed -n '2,/^$/p' >&2
        exit 1
    fi
    tip=$(git commit-tree "$tree" -p "$tip" -p "refs/integration/$topic" -m "Merge branch '$topic'")
done

index=$(mktemp -d)/index
GIT_INDEX_FILE=$index git read-tree "$tip"
GIT_INDEX_FILE=$index git update-index --add --cacheinfo "100755,$script,integration.sh"
tree=$(GIT_INDEX_FILE=$index git write-tree)
rm -r "$(dirname "$index")"
tip=$(git commit-tree "$tree" -p "$tip" -m "integration.sh: the script that builds this branch")

if [ -n "$old" ] && [ "$(git rev-parse "$old^{tree}")" = "$tree" ]; then
    echo "$BRANCH is up to date: $old"
    exit 0
fi
git log --oneline --first-parent "refs/integration/main~1..$tip"

if [ "${1:-}" = push ]; then
    refs=("+$tip:refs/heads/$BRANCH")
    [ -z "$old" ] || refs+=("$old:refs/tags/integration/$(date +%F)-$(git rev-parse --short "$old")")
    git push --atomic --force-with-lease="refs/heads/$BRANCH:$old" "$PUSH" "${refs[@]}"
    echo "Pushed $BRANCH: $tip"
else
    echo "Built $tip; run with 'push' to publish it."
fi
