# Version tracking

- For every completed update, increment `APP_VERSION` in `app/main.py` and add a matching numbered entry at the top of `CHANGELOG.md` in the same change. Include UI fixes and installation/documentation updates.
- Continue patch increments for incremental updates (the next after 1.19.13 is 1.19.14); use a minor or major increment when the scope warrants it. Never reuse or decrease a version.
- Keep the README's current source version synchronized. The UI, health endpoint, and OpenAPI metadata must derive their version from `APP_VERSION`.
- Run `python tools/check_version.py --base-ref <base-commit>` before publishing. CI enforces a version increase for changed revisions and checks changelog/README consistency.
- Do not rewrite old commits or move existing release tags to repair version history. Mark retrospective changelog entries honestly.
- Change pinned Docker image versions only after those images are actually published. A source-version bump does not itself publish a GitHub release or Docker image.
