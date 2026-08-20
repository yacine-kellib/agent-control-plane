#!/usr/bin/env bash
# Cut a signed release: gate, sign, commit, verify, tag, push -- in that order,
# refusing at the first thing that is not true.
#
# WHY THIS EXISTS. The flow was about ten hand-run commands and on 2026-08-20 it
# went wrong twice in one release. A push written as
# `git push origin <branch>:main <tag>` lost its refspec and ran as a bare
# `git push origin`; git then suggested `--set-upstream origin <branch>`, which
# would have created a branch named after a local working branch on the PUBLIC
# repository. Neither mistake was caught by anything -- there was nothing to
# catch them.
#
# The ordering is the safety property, not a convenience:
#
#   gate green  ->  sign  ->  commit  ->  FULL verify  ->  tag  ->  push
#
# Signing before the gate would sign a red tree. Tagging before the full verify
# would tag bytes whose signature had never been checked. Pushing the tag before
# the branch would publish a tag pointing at a commit the remote does not have.
#
#   ./tools/release.sh 1.3.16
#
# The passphrase prompt is the one genuinely manual step and REQUIRES A REAL
# TERMINAL. It is never taken from a flag, a file or the environment: a
# passphrase passed as an argument lands in the shell history and in any
# transcript watching the session.
set -uo pipefail
cd "$(dirname "$0")/.."

die() { printf '\n  \033[31mHALT\033[0m %s\n\n' "$1"; exit 1; }
ok()  { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
step(){ printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

VERSION="${1:-}"
KEY="${2:-$HOME/acp-release-v3.key}"
REMOTE_BRANCH=main

[ -n "$VERSION" ] || die "usage: ./tools/release.sh <version> [keyfile]   e.g. ./tools/release.sh 1.3.16"
VERSION="${VERSION#v}"
case "$VERSION" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "'$VERSION' is not a version. Expected MAJOR.MINOR.PATCH." ;;
esac
TAG="v$VERSION"

printf '\n\033[1m== release %s ==\033[0m\n' "$TAG"
printf '  branch : %s -> origin/%s\n' "$(git branch --show-current)" "$REMOTE_BRANCH"
printf '  key    : %s\n' "$KEY"

# --- 0. preconditions -----------------------------------------------------------
step "0. preconditions"

[ -t 0 ] || die "no terminal. Signing needs a TTY for the passphrase prompt and must fail closed rather than hang or read a secret from elsewhere."
ok "running on a real terminal, so the passphrase can be prompted for"

[ -f "$KEY" ] || die "no key at $KEY. Pass the path as the second argument if it lives elsewhere."
ok "release key is present"

# A dirty tree is the one that gets signed, and the commit would not contain it.
[ -z "$(git status --porcelain)" ] || die "working tree is dirty. Commit or stash everything first — the manifest signs what is ON DISK, and anything uncommitted would be signed and then lost."
ok "working tree is clean, so what gets signed is what gets committed"

# git tag tags whatever HEAD is. A tag was once created on the wrong branch in
# this project and would have published 49 private commits and a strategy
# document; it was caught by hand before the push. Hence an explicit check that
# the tag does not exist, locally or on the remote, before anything is signed.
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG already exists locally. Delete it deliberately (git tag -d $TAG) or pick another version."
[ -z "$(git ls-remote --tags origin "refs/tags/$TAG" 2>/dev/null)" ] || die "tag $TAG is already on the remote. A published tag is immutable — pick the next version."
ok "$TAG does not exist locally or on the remote"

# The push below is a fast-forward or it is nothing. A force-push to a public
# main rewrites history other people may already have.
git fetch -q origin "$REMOTE_BRANCH" 2>/dev/null || true
if git rev-parse -q --verify "origin/$REMOTE_BRANCH" >/dev/null; then
  git merge-base --is-ancestor "origin/$REMOTE_BRANCH" HEAD \
    || die "origin/$REMOTE_BRANCH is NOT an ancestor of HEAD. This push would not be a fast-forward. Reconcile by hand — this script will not force."
  ok "origin/$REMOTE_BRANCH is an ancestor of HEAD, so the push is a fast-forward"
fi

# --- 1. the gate ----------------------------------------------------------------
step "1. the gate (this is what the signature will mean)"
./tools/verify.sh --suites || die "the suites gate is RED. Nothing was signed. A signature over a failing tree is worse than no release."
ok "suites gate is green"

./tools/selftest.sh >/dev/null 2>&1 || die "selftest.sh is RED. Run ./tools/selftest.sh to see which assertion. Nothing was signed."
ok "tooling self-test is green"

# --- 2. sign --------------------------------------------------------------------
step "2. sign (prompts for the passphrase)"
./tools/sign-release.sh sign "$KEY" || die "signing failed. sign-release.sh builds into .tmp files and moves them only after the signature exists, so the previous MANIFEST.sha256 is intact."
ok "manifest signed"

git add MANIFEST.sha256 MANIFEST.sha256.sig
git commit -q -m "release: sign $TAG" || die "nothing to commit — did the manifest actually change?"
ok "manifest and signature committed"

# --- 3. the FULL gate, which the suites gate cannot do --------------------------
# Sections 1 and 2 -- integrity and signature -- are the two the per-commit gate
# skips because they need the offline key. This is the only moment they can be
# green, so it is the only moment they are worth checking.
step "3. full verify (integrity + signature)"
./tools/verify.sh || die "FULL verify is red after signing. Do NOT tag. Do not regenerate the manifest to make it green — a manifest whose signature does not verify is strictly worse than a stale one."
ok "integrity and signature both verify"

# --- 4. tag ---------------------------------------------------------------------
step "4. tag"
git tag "$TAG" || die "could not create tag $TAG"
[ "$(git rev-parse "$TAG^{commit}")" = "$(git rev-parse HEAD)" ] || die "tag $TAG does not point at HEAD"
ok "$TAG created, pointing at $(git rev-parse --short HEAD)"

# --- 5. push, branch first, one ref per command ---------------------------------
# ONE REF PER COMMAND, deliberately. A single command carrying several refspecs
# is the exact shape that failed on 2026-08-20: the tail was lost and it ran as a
# bare `git push origin`, which does something ELSE rather than failing. A
# truncated form of the two commands below cannot push the wrong thing.
#
# Branch before tag: a tag pushed first names a commit the remote does not yet
# have, and anyone fetching in that window gets a tag they cannot resolve.
step "5. push"
git push origin "HEAD:$REMOTE_BRANCH" || die "branch push failed. If it was rejected for token scope, retry with:
    git -c credential.helper= -c 'credential.https://github.com.helper=!gh auth git-credential' push origin HEAD:$REMOTE_BRANCH
Nothing is broken — the tag is local and unpushed."
ok "branch pushed to origin/$REMOTE_BRANCH"

git push origin "refs/tags/$TAG" || die "TAG push failed but the branch landed. Retry just the tag: git push origin refs/tags/$TAG"
ok "tag pushed"

# --- 6. confirm from the remote, not from our own success --------------------
# A push that printed no error is a claim. What the remote actually holds is the
# fact, and this whole file exists because those two came apart once already.
step "6. confirm against the remote"
R_BRANCH=$(git ls-remote origin "refs/heads/$REMOTE_BRANCH" | awk '{print $1}')
R_TAG=$(git ls-remote origin "refs/tags/$TAG" | awk '{print $1}')
LOCAL=$(git rev-parse HEAD)
[ "$R_BRANCH" = "$LOCAL" ] || die "origin/$REMOTE_BRANCH is $R_BRANCH, expected $LOCAL"
[ "$R_TAG" = "$LOCAL" ]    || die "remote tag $TAG is $R_TAG, expected $LOCAL"
ok "origin/$REMOTE_BRANCH and $TAG both at $(git rev-parse --short HEAD)"

printf '\n\033[1m== Result ==\033[0m\n'
printf '  %s is signed, tagged and public.\n\n' "$TAG"
printf '  Next, in the product repository:\n'
printf '    ./tools/bump-pin.sh %s\n\n' "$TAG"
