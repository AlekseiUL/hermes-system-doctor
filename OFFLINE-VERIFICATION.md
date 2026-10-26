# Offline verification boundary

Versioned profile/gateway/read-only fixture contract.

## Reproduce

`python -m pytest`

Fixtures are synthetic snapshots, not proof of health on a live Hermes host or every OS. No service restart or platform delivery is performed.

## Rollback

Review the commit diff and use a new checkout of the pre-change commit for source rollback. Keep user data and live installations untouched. A source rollback is not permission to restore unsafe network exposure or bypass approval.
