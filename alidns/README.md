# alidns

Caddy DNS providers for Alibaba Cloud: **AliDNS** (云解析 DNS) and **ESA** (边缘安全加速).

Two modules, two products, one binary:

| Caddyfile | Module ID | Product |
| --- | --- | --- |
| `alidns` | `dns.providers.alidns` | 云解析 DNS (classic hosted DNS) |
| `esa` | `dns.providers.esa` | 边缘安全加速 ESA (CDN/WAF with DNS) |

Pick by how the domain is onboarded: **ESA in NS mode** → `esa`; **classic
云解析 DNS** → `alidns`. Both may be used in the same Caddyfile.

## Fork

Forked from [caddy-dns/alidns](https://github.com/caddy-dns/alidns), MIT © 2020 Yu Zhu.
Original copyright and permission notice retained verbatim in [LICENSE](LICENSE),
as the MIT License requires.

The fork adds the `esa` provider and fixes correctness bugs in the shared
Caddy plumbing. See [Changes vs upstream](#changes-vs-upstream).

## Usage

```
{
    acme_dns esa {
        access_key_id  "{$ALIYUN_ACCESS_KEY_ID}"
        access_key_secret "{$ALIYUN_ACCESS_KEY_SECRET}"
    }
}
```

Per site (needed to mix both providers):

```
*.example.com {
    tls {
        dns esa {
            access_key_id  "{$ALIYUN_ACCESS_KEY_ID}"
            access_key_secret "{$ALIYUN_ACCESS_KEY_SECRET}"
        }
    }
}
```

`alidns` takes the same four directives but has no shorthand form:

```
tls {
    dns alidns {
        access_key_id     "{$ALIYUN_ACCESS_KEY_ID}"
        access_key_secret "{$ALIYUN_ACCESS_KEY_SECRET}"
        region_id         "cn-hangzhou"   # optional, default cn-hangzhou
        security_token    "{$ALIYUN_SECURITY_TOKEN}"   # STS only
    }
}
```

### Directives

| Directive | Required | Providers | Notes |
| --- | --- | --- | --- |
| `access_key_id` | yes | both | |
| `access_key_secret` | yes | both | |
| `security_token` | no | both | STS / RAM-role credentials only |
| `region_id` | no | both | Default `cn-hangzhou`. ESA derives its endpoint as `esa.<region_id>.aliyuncs.com`. |

Missing keys fail at `caddy validate` time, not during certificate issuance.

### Requirements

- A RAM user with least privilege. For ESA: `esa:ListSites`, `esa:CreateRecord`,
  `esa:DeleteRecord`, `esa:ListRecords`.
- **ESA sites must be onboarded in NS mode.** CNAME-mode sites reject TXT
  records (`InvalidParameter.CnameSiteRecordUnsupport`), so DNS-01 cannot work.
  Classic AliDNS has no such restriction.

## Build

```bash
xcaddy build --with github.com/nuln/caddy-plugins/alidns
```

Pin a version, or track the branch:

```bash
xcaddy build --with github.com/nuln/caddy-plugins/alidns@v1.0.0
xcaddy build --with github.com/nuln/caddy-plugins/alidns@main
```

Locally, from a checkout of the monorepo:

```bash
xcaddy build --with github.com/nuln/caddy-plugins/alidns@v0.0.0=/path/to/caddy-plugins/alidns
```

Verify:

```bash
caddy list-modules | grep dns.providers
# dns.providers.alidns
# dns.providers.esa
```

This directory is its own Go module inside
[nuln/caddy-plugins](https://github.com/nuln/caddy-plugins) and is versioned
independently via `alidns/v*` tags. See the repository README for the scheme.

## Changes vs upstream

`alidns` behaviour is unchanged apart from bug fixes. Added:

- **`esa` provider** — `ListSites` site lookup with per-zone caching, then
  `CreateRecord` / `ListRecords` / `DeleteRecord` for the `_acme-challenge` TXT.
  NS-mode sites only.

Fixes applied to both providers:

- Errors from `DeleteRecords` are no longer swallowed. certmagic treats a nil
  error as "challenge cleaned up", so a leaked TXT record used to break the
  *next* issuance with `Record.RecordNameConflictWithSameRecordType`.
- `getSiteID` no longer reports an API/auth failure as "site not found", which
  sent users hunting for domain problems that did not exist.
- `GetRecords` pagination no longer depends on `TotalCount`, which ESA may omit;
  results were silently truncated to page 1.
- Lazy client init is race-free (`go test -race` clean).
- All methods honour context cancellation.
- Incomplete credentials fail at config load via `caddy.Validator`.
- `region_id` placeholders are now resolved by `Provision`, like the other fields.

Removed: the `aliesa` module alias. It had never been released, so there was
nothing to stay compatible with.

## Development

```bash
go test ./...            # unit tests, no credentials needed
go test -race ./...
go vet ./...
gofmt -l .
```

The ESA record logic is tested through a fake of the four ESA SDK calls it uses
(`esaAPI`), so the suite runs offline. The AliDNS side wraps
`github.com/libdns/alidns`; only its Caddy plumbing is tested here.

Run these from this directory — it is a separate module, and the repository
root is not a Go module.

CI runs on every push and weekly, including an xcaddy build against the latest
Caddy release — see
[../.github/workflows/ci.yml](../.github/workflows/ci.yml).

## License

MIT — see [LICENSE](LICENSE).
