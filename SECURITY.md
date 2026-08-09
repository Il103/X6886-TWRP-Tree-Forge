# Token and source security

- Never commit or paste `TREE_PUSH_TOKEN` into this repository, a log, an issue, or chat.
- Add the token only as a GitHub Actions secret named `TREE_PUSH_TOKEN`.
- The workflow is manual (`workflow_dispatch`) and does not run untrusted pull-request code.
- Publishing uses `GIT_ASKPASS`; the token is never placed in a remote URL or printed.
- The raw Device Info HW PDF is not published because it contains local IP/session data.
- The tool accepts only HTTPS GitHub/GitLab dump URLs by default.
- Generated provenance contains source hashes and paths, never credentials.

For a public output repository, a classic PAT with `public_repo` is sufficient. For a private output repository use `repo`. Revoke and replace a token immediately if it is exposed.
