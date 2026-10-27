# Release candidate v0.1.1-alpha.1

Status: prepared, not published. Publish only after the exact PR head passes CI and the owner approves merge/release. Existing tags must not move.

Distribution: Python wheel and source archive. This candidate includes all changes on main since v0.1.0, plus pinned GitHub Actions and review-first dependency updates. This is not an npm/PyPI publication.

Keep the GitHub prerelease flag enabled. Alpha status is not a stable support promise.

Install into a fresh temporary environment from the built archive, not an editable checkout. Run the documented offline core command/fixture before publishing; do not enable profiles, contact paid providers or start services. After release, download the exact public artifact and repeat this check.

Rollback: close the unmerged PR; after merge, submit a revert PR. Do not rewrite the release tag or delete old artifacts. A bad release must be superseded and clearly marked, with owner approval.
