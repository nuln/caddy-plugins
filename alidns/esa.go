// Package alidns provides Caddy DNS providers for Alibaba Cloud DNS (AliDNS)
// and Alibaba Cloud Edge Security Acceleration (ESA).
//
// Only two ESA operations are needed for DNS-01 ACME challenges: add a TXT
// record for _acme-challenge.<domain>, then delete it again once the CA has
// validated it. Everything else in this file exists to satisfy Caddy's
// requirements for the global `dns` block and for ECH, which demand the full
// libdns surface (RecordGetter/Append/Set/Delete).
package alidns

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	esa "github.com/alibabacloud-go/esa-20240910/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

const (
	// defaultRegionID is ESA's global default region, reachable from anywhere,
	// so it only needs overriding for an account pinned to one region.
	defaultRegionID = "cn-hangzhou"

	// defaultTTL is used when the caller asks for no TTL at all. certmagic
	// defaults `dns_ttl` to 0, and ESA requires the field, so something has to
	// fill the gap. 30s matches the ESA console default and keeps ACME
	// propagation checks fast.
	defaultTTL = 30

	// maxPageSize is ESA's documented ListRecords page limit.
	maxPageSize = 500

	// siteSearchPageSize is ample for an exact-name ListSites match, which can
	// return at most one site.
	siteSearchPageSize = 20
)

// esaAPI is the slice of the ESA SDK this provider uses.
//
// It exists so the record logic can be tested without a live ESA account.
// *esa.Client satisfies it.
type esaAPI interface {
	ListSites(request *esa.ListSitesRequest) (*esa.ListSitesResponse, error)
	ListRecords(request *esa.ListRecordsRequest) (*esa.ListRecordsResponse, error)
	CreateRecord(request *esa.CreateRecordRequest) (*esa.CreateRecordResponse, error)
	DeleteRecord(request *esa.DeleteRecordRequest) (*esa.DeleteRecordResponse, error)
}

// ESAProvider implements the libdns interfaces for Alibaba Cloud ESA.
//
// It is not safe to copy after first use: it embeds a mutex and two caches.
type ESAProvider struct {
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	SecurityToken   string `json:"security_token,omitempty"`
	RegionID        string `json:"region_id,omitempty"`

	mu     sync.Mutex
	client esaAPI
	sites  sync.Map // lower-cased zone -> ESA SiteId (int64)
}

// ESA wraps ESAProvider as a Caddy module.
type ESA struct {
	*ESAProvider
}

func init() {
	caddy.RegisterModule(ESA{})
}

func (ESA) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.esa",
		New: func() caddy.Module { return &ESA{ESAProvider: new(ESAProvider)} },
	}
}

// Provision resolves {env.*} / {file.*} placeholders in the credentials.
func (p *ESA) Provision(_ caddy.Context) error {
	if p.ESAProvider == nil {
		p.ESAProvider = new(ESAProvider)
	}
	repl := caddy.NewReplacer()
	p.AccessKeyID = repl.ReplaceAll(p.AccessKeyID, "")
	p.AccessKeySecret = repl.ReplaceAll(p.AccessKeySecret, "")
	p.SecurityToken = repl.ReplaceAll(p.SecurityToken, "")
	p.RegionID = repl.ReplaceAll(p.RegionID, "")
	return nil
}

// Validate rejects an incomplete key set at config-load time instead of letting
// the first certificate issuance fail — which, with a default ACME schedule,
// can be a month later and only shows up in the ACME logs.
func (p *ESA) Validate() error {
	if p.ESAProvider == nil || p.AccessKeyID == "" || p.AccessKeySecret == "" {
		return fmt.Errorf("access_key_id and access_key_secret are both required")
	}
	return nil
}

// UnmarshalCaddyfile parses Caddyfile tokens:
//
//	esa {
//	    access_key_id "<access_key_id>"
//	    access_key_secret "<access_key_secret>"
//	    security_token "<security_token, optional: only for STS/RAM role credentials>"
//	    region_id "<region_id, optional: defaults to cn-hangzhou>"
//	}
//
// Or shorthand:
//
//	esa <access_key_id> <access_key_secret>
func (p *ESA) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if p.ESAProvider == nil {
		p.ESAProvider = new(ESAProvider)
	}

	for d.Next() {
		if d.NextArg() {
			p.AccessKeyID = d.Val()
			if d.NextArg() {
				p.AccessKeySecret = d.Val()
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			continue
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
			case "security_token":
				if !d.Args(&p.SecurityToken) {
					return d.ArgErr()
				}
			case "region_id":
				if !d.Args(&p.RegionID) {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}

	return p.Validate()
}

func (p *ESAProvider) getClient() (esaAPI, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		return p.client, nil
	}
	// Defence in depth behind (*ESA).Validate: without a key the ESA API
	// answers with an opaque signature error instead of a useful one.
	if p.AccessKeyID == "" || p.AccessKeySecret == "" {
		return nil, fmt.Errorf("missing access_key_id or access_key_secret")
	}

	region := p.RegionID
	if region == "" {
		region = defaultRegionID
	}
	config := &openapi.Config{
		AccessKeyId:     dara.String(p.AccessKeyID),
		AccessKeySecret: dara.String(p.AccessKeySecret),
		RegionId:        dara.String(region),
		Endpoint:        dara.String(fmt.Sprintf("esa.%s.aliyuncs.com", region)),
	}
	if p.SecurityToken != "" {
		config.SecurityToken = dara.String(p.SecurityToken)
	}

	client, err := esa.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create ESA client: %w", err)
	}
	p.client = client
	return client, nil
}

// getClientAndSiteID is the shared preamble of every libdns method: build the
// API client and map the DNS zone onto the ESA site that serves it.
func (p *ESAProvider) getClientAndSiteID(ctx context.Context, zone string) (esaAPI, int64, error) {
	// certmagic cancels this context on timeout, and the SDK's non-WithOptions
	// calls have no context of their own, so honour cancellation ourselves.
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	client, err := p.getClient()
	if err != nil {
		return nil, 0, err
	}
	siteID, err := p.getSiteID(client, zone)
	if err != nil {
		return nil, 0, err
	}
	return client, siteID, nil
}

// getSiteID resolves the ESA site ID serving zone. certmagic derives zone from
// the zone's SOA record (so it arrives as an FQDN with a trailing dot) and ESA
// calls the equivalent concept a "site", which is always registered without the
// trailing dot. Results are cached for the process lifetime; a Caddy reload
// builds a fresh module instance and therefore a fresh cache.
func (p *ESAProvider) getSiteID(client esaAPI, zone string) (int64, error) {
	cleanZone := strings.ToLower(strings.Trim(zone, "."))
	if val, ok := p.sites.Load(cleanZone); ok {
		return val.(int64), nil
	}

	// Walk up the labels: an ESA site is usually the registrable domain, but a
	// user may have onboarded the exact zone as its own site instead.
	for _, candidate := range siteCandidates(zone) {
		resp, err := client.ListSites(&esa.ListSitesRequest{
			SiteName:       dara.String(candidate),
			SiteSearchType: dara.String("exact"),
			PageSize:       dara.Int32(siteSearchPageSize),
		})
		if err != nil {
			// Deliberately not swallowed: the overwhelmingly common causes here
			// are a wrong AccessKey or a missing RAM policy, and reporting those
			// as "site not found" sends users hunting for a domain problem that
			// does not exist.
			return 0, fmt.Errorf("ESA ListSites(%q): %w", candidate, err)
		}
		if resp.Body != nil {
			for _, site := range resp.Body.Sites {
				if site.SiteId == nil || !strings.EqualFold(dara.StringValue(site.SiteName), candidate) {
					continue
				}
				p.sites.Store(cleanZone, *site.SiteId)
				return *site.SiteId, nil
			}
		}
	}

	return 0, fmt.Errorf("no ESA site found for zone %q; onboard the domain in ESA in NS mode first", zone)
}

// AppendRecords creates the given records. It never modifies existing records,
// which is exactly what certmagic needs when it publishes a challenge token.
func (p *ESAProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	client, siteID, err := p.getClientAndSiteID(ctx, zone)
	if err != nil {
		return nil, err
	}

	added := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		if err := ctx.Err(); err != nil {
			return added, err
		}

		rr := rec.RR()
		ttl := rr.TTL.Seconds()
		if ttl <= 0 || ttl > math.MaxInt32 {
			ttl = defaultTTL
		}

		_, err := client.CreateRecord(&esa.CreateRecordRequest{
			SiteId:     dara.Int64(siteID),
			RecordName: dara.String(fqdn(zone, rr.Name)),
			Type:       dara.String(rr.Type),
			Data:       &esa.CreateRecordRequestData{Value: dara.String(rr.Data)},
			Ttl:        dara.Int32(int32(ttl)),
		})
		if err != nil {
			return added, fmt.Errorf("ESA create %s record %s: %w", rr.Type, fqdn(zone, rr.Name), err)
		}
		added = append(added, asRecord(rr))
	}
	return added, nil
}

// DeleteRecords removes the records that exactly match the input, returning the
// ones it actually deleted.
func (p *ESAProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	client, siteID, err := p.getClientAndSiteID(ctx, zone)
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record
	for _, rec := range recs {
		if err := ctx.Err(); err != nil {
			return deleted, err
		}

		rr := rec.RR()
		name := fqdn(zone, rr.Name)

		// ESA has no "delete by name+type+value" API, so list first. Filter on
		// the value client-side because ListRecords cannot do it server-side.
		listReq := &esa.ListRecordsRequest{
			SiteId:          dara.Int64(siteID),
			RecordName:      dara.String(name),
			RecordMatchType: dara.String("exact"),
			PageSize:        dara.Int32(maxPageSize),
		}
		if rr.Type != "" {
			listReq.Type = dara.String(rr.Type)
		}

		listResp, err := client.ListRecords(listReq)
		if err != nil {
			// Must not be swallowed. certmagic treats a nil error as "challenge
			// cleaned up" and logs success, so a leaked _acme-challenge TXT
			// record silently breaks the *next* issuance with
			// Record.RecordNameConflictWithSameRecordType.
			return deleted, fmt.Errorf("ESA list records for %s: %w", name, err)
		}
		if listResp.Body == nil {
			continue
		}

		for _, r := range listResp.Body.Records {
			if r == nil || r.RecordId == nil {
				continue
			}
			// libdns contract: empty Data means "delete whatever is at this name";
			// otherwise the value must match exactly. Comparing loosely here would
			// let a delete request remove a record the caller did not name, which
			// is worse than reporting a mismatch.
			if rr.Data != "" {
				var esaValue string
				if r.Data != nil {
					esaValue = dara.StringValue(r.Data.Value)
				}
				if rr.Data != esaValue {
					continue
				}
			}
			if _, err := client.DeleteRecord(&esa.DeleteRecordRequest{RecordId: r.RecordId}); err != nil {
				return deleted, fmt.Errorf("ESA delete record %d (%s): %w", *r.RecordId, name, err)
			}
			deleted = append(deleted, asRecord(rr))
		}
	}
	return deleted, nil
}

// GetRecords lists every record in the zone. certmagic itself never calls it,
// but Caddy's global `dns` block and ECH do, and both require the full libdns
// surface before they will load the module at all.
func (p *ESAProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	client, siteID, err := p.getClientAndSiteID(ctx, zone)
	if err != nil {
		return nil, err
	}

	var records []libdns.Record
	for page := int32(1); ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		resp, err := client.ListRecords(&esa.ListRecordsRequest{
			SiteId:     dara.Int64(siteID),
			PageNumber: dara.Int32(page),
			PageSize:   dara.Int32(maxPageSize),
		})
		if err != nil {
			return nil, fmt.Errorf("ESA list records for zone %s: %w", zone, err)
		}
		if resp.Body == nil || len(resp.Body.Records) == 0 {
			break
		}

		for _, r := range resp.Body.Records {
			if r == nil {
				continue
			}
			var value string
			if r.Data != nil {
				value = dara.StringValue(r.Data.Value)
			}
			records = append(records, asRecord(libdns.RR{
				Type: dara.StringValue(r.RecordType),
				Name: libdns.RelativeName(dara.StringValue(r.RecordName), zone),
				TTL:  time.Duration(dara.Int64Value(r.Ttl)) * time.Second,
				Data: value,
			}))
		}

		// Stop on a short page rather than trusting TotalCount: when ESA omits
		// TotalCount the count comparison would silently truncate to page 1.
		if len(resp.Body.Records) < int(maxPageSize) {
			break
		}
	}
	return records, nil
}

// SetRecords makes each (name, type) pair in recs the only member of its RRset
// in the zone. Everything else is left alone.
func (p *ESAProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	existing, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Collect the whole stale set up front so the RRset is replaced with one
	// ListRecords + one delete pass, instead of a fresh lookup per input record.
	var stale []libdns.Record
	for _, ex := range existing {
		exRR := ex.RR()
		for _, rec := range recs {
			rr := rec.RR()
			if strings.EqualFold(exRR.Name, rr.Name) && strings.EqualFold(exRR.Type, rr.Type) {
				stale = append(stale, ex)
				break
			}
		}
	}

	if _, err := p.DeleteRecords(ctx, zone, stale); err != nil {
		return nil, err
	}
	return p.AppendRecords(ctx, zone, recs)
}

// siteCandidates returns zone and each of its parent domains, most specific
// first, which is the order an ESA site may be registered under. certmagic
// hands us the zone apex from the SOA record, always as an FQDN with a trailing
// dot; ESA site names are stored lower-cased and without it.
func siteCandidates(zone string) []string {
	var candidates []string
	for curr := strings.ToLower(strings.Trim(zone, ".")); curr != ""; {
		candidates = append(candidates, curr)
		_, curr, _ = strings.Cut(curr, ".") // drop the leftmost label
	}
	return candidates
}

// fqdn expands a zone-relative record name into the absolute name ESA expects.
// ESA rejects an empty RecordName, so the zone apex is spelled out rather than
// relying on "@".
func fqdn(zone, name string) string {
	return strings.TrimSuffix(libdns.AbsoluteName(name, zone), ".")
}

// asRecord upgrades an opaque RR to its concrete libdns type (TXT, A, MX, ...)
// so callers can type-assert the result, as the libdns contract requires. Types
// libdns does not model stay as the raw RR.
func asRecord(rr libdns.RR) libdns.Record {
	if rec, err := rr.Parse(); err == nil {
		return rec
	}
	return rr
}

// Interface guards
var (
	_ caddy.Module          = (*ESA)(nil)
	_ caddy.Provisioner     = (*ESA)(nil)
	_ caddy.Validator       = (*ESA)(nil)
	_ caddyfile.Unmarshaler = (*ESA)(nil)
	_ libdns.RecordGetter   = (*ESAProvider)(nil)
	_ libdns.RecordAppender = (*ESAProvider)(nil)
	_ libdns.RecordSetter   = (*ESAProvider)(nil)
	_ libdns.RecordDeleter  = (*ESAProvider)(nil)
	_ esaAPI                = (*esa.Client)(nil)
)
