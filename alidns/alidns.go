package alidns

import (
	"fmt"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/alidns"
)

// Provider wraps the provider implementation as a Caddy module.
type Provider struct{ *alidns.Provider }

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.alidns",
		New: func() caddy.Module { return &Provider{new(alidns.Provider)} },
	}
}

// Provision resolves {env.*} / {file.*} placeholders in the credentials.
// Implements caddy.Provisioner.
func (p *Provider) Provision(_ caddy.Context) error {
	if p.Provider == nil {
		p.Provider = new(alidns.Provider)
	}
	repl := caddy.NewReplacer()
	p.AccessKeyID = repl.ReplaceAll(p.AccessKeyID, "")
	p.AccessKeySecret = repl.ReplaceAll(p.AccessKeySecret, "")
	p.SecurityToken = repl.ReplaceAll(p.SecurityToken, "")
	// RegionID was previously left unresolved, so `region_id "{env.X}"` was
	// passed through to the API as a literal placeholder.
	p.RegionID = repl.ReplaceAll(p.RegionID, "")
	return nil
}

// Validate rejects an incomplete key set at config-load time. Without it a JSON
// config missing the secret loads without complaint and then fails during the
// first certificate issuance, which by default may be a month away.
// Implements caddy.Validator.
func (p *Provider) Validate() error {
	if p.Provider == nil || p.AccessKeyID == "" || p.AccessKeySecret == "" {
		return fmt.Errorf("access_key_id and access_key_secret are both required")
	}
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	alidns {
//	    access_key_id "<access_key_id>"
//	    access_key_secret "<access_key_secret>"
//	    region_id "<region_id, defaults to 'cn-hangzhou' if empty>"
//	    security_token "<security_token, if you use the STS authorization it's required by aliyun>"
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if p.Provider == nil {
		p.Provider = new(alidns.Provider)
	}

	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "access_key_id":
				if !d.Args(&p.AccessKeyID) {
					return d.ArgErr()
				}
			case "access_key_secret":
				if !d.Args(&p.AccessKeySecret) {
					return d.ArgErr()
				}
			case "region_id":
				if !d.Args(&p.RegionID) {
					return d.ArgErr()
				}
			case "security_token":
				if !d.Args(&p.SecurityToken) {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}

	return p.Validate()
}

// Interface guards
var (
	_ caddy.Module          = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ caddy.Validator       = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
)
