# Fork workflows

The fork's default branch is `preview`. API lint/tests, web checks, migration checks and copyright checks run on pushes and pull requests to it, and support manual dispatch. Jobs do not require a requested reviewer. i18n's manual dispatch also runs its check.

## Container images

**Fork container images** builds the frontend, space, admin, live, backend and proxy images on pushes to `preview`/`canary` that affect build inputs, or on manual dispatch. It publishes to:

```text
ghcr.io/<repository-owner>/plane-frontend
ghcr.io/<repository-owner>/plane-space
ghcr.io/<repository-owner>/plane-admin
ghcr.io/<repository-owner>/plane-live
ghcr.io/<repository-owner>/plane-backend
ghcr.io/<repository-owner>/plane-proxy
```

Each image gets a branch tag, such as `preview`, and a `sha-<full-commit-sha>` tag. Use commit tags for reproducible deployments. Default builds use native AMD64 runners; selecting `arm64` during manual dispatch adds a native ARM64 build and publishes a combined manifest. A later default push replaces the branch tag with its AMD64 build; ARM64 deployments should pin the commit tag from an ARM64-enabled run.

Publishing uses the repository's automatic `GITHUB_TOKEN` with `packages: write`, so no upstream Docker Hub credentials are required. GitHub Actions must be enabled on the fork. If an organization restricts package creation, its policy must permit these packages. New GHCR packages may be private: either give the deployment credentials permission to pull them or explicitly change package visibility in GitHub.

The original **Branch Build CE** and **Feature Preview** pipelines run only in `makeplane/plane`. They depend on upstream Docker Hub, release and Kubernetes/Tailscale infrastructure. Fork container publishing replaces the branch image build; it does not deploy an application, create a release or build the upstream all-in-one image. Configure your deployment to consume the fork images rather than `makeplane/*` images.

## Checks

The API workflow runs the OIDC suite and existing app authentication regressions against isolated PostgreSQL, Redis, RabbitMQ and object-storage services. Migration checks verify model/migration consistency. Web checks retain the existing Turbo affected-package selection, with a base commit for push/manual runs.

CodeQL and React Doctor retain their existing triggers. GitHub may still list historical workflows that are no longer present in this branch; those have no current workflow file to run. No repository secret is copied from upstream.
