# Dependency maintenance

Dependabot opens weekly review-first pull requests for the applicable manifests and GitHub Actions. There is no auto-merge. Keep existing SHA pins and review upstream changes before accepting updates.

The weekly dependency-audit workflow blocks every advisory in `requirements-audit.txt`, a complete pinned dependency snapshot (Python 3.12). It uses `pip-audit --strict --disable-pip --no-deps`; no target package is installed or executed by this audit. Runtime, optional and build/test dependencies are included where declared. This snapshot is not a claim about arbitrary caller-installed packages or optional external services.

Regenerate the snapshot when a dependency manifest changes. Review the diff, run the audit and the full regression/install gate before merging. Keep the snapshot aligned with the existing uv.lock/requirements-ci.lock when present. Do not suppress advisories to obtain green CI.

Build/test input: `requirements-build.in`; compile it with `pyproject.toml --all-extras` using uv pip compile. Existing uv projects must export their frozen lock as constraints first.
