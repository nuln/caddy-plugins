# caddy-plugins

Caddy DNS provider plugins, maintained together but released independently.

## Plugins

| Directory | Module path | Version tag | Upstream |
| --- | --- | --- | --- |
| [`alidns/`](alidns/) | `github.com/nuln/caddy-plugins/alidns` | `alidns/v*` | fork of [caddy-dns/alidns](https://github.com/caddy-dns/alidns) (MIT © 2020 Yu Zhu) |

Least-privilege RAM policies ship with the plugin, one file per service — see
[alidns/README.md](alidns/README.md#ram-permissions).

## Independent versioning

Each plugin directory is its own Go module with its own `go.mod`, so versions
are released per plugin using a directory-scoped tag. `alidns/` is at `v1.0.0`
while the repository itself has no tags at all.

```bash
# install a specific version
xcaddy build --with github.com/nuln/caddy-plugins/alidns@v1.0.0

# track the latest release of just this plugin
xcaddy build --with github.com/nuln/caddy-plugins/alidns

# pin to the branch while developing
xcaddy build --with github.com/nuln/caddy-plugins/alidns@main
```

Release a new version of one plugin:

```bash
git tag alidns/v1.1.0
git push origin alidns/v1.1.0
```

The tag must carry the directory prefix. A bare `v1.1.0` would be ambiguous the
moment a second plugin is added, so it is not used.

Note that `@main` resolves to the current state of the whole repository, so a
breaking change in one plugin can break builds pinned to `@main` for another.
Prefer a version tag for anything reproducible.

## Adding a plugin

1. Create the directory and give it a `go.mod` whose module path is
   `github.com/nuln/caddy-plugins/<dir>`.
2. Register it in `.github/workflows/ci.yml`.
3. Add a row to the table above.
4. Tag its first release as `<dir>/v0.1.0`.

There is deliberately no `go.mod` at the repository root: the root is not a Go
module, and nothing imports it.

## CI

`.github/workflows/ci.yml` runs on every push and weekly:

- `gofmt`, `go vet`, `go test -race`, a coverage floor, and a `go mod tidy`
  idempotency check
- xcaddy builds against both the latest Caddy release and the version pinned in
  each plugin's `go.mod`, then asserts the modules register and a real Caddyfile
  loads

The weekly schedule is what surfaces a new Caddy release that breaks a plugin,
before anyone tries to build it.

## License

MIT — see [LICENSE](LICENSE). Third-party notices are preserved in each plugin
directory.
