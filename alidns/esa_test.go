package alidns

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	esa "github.com/alibabacloud-go/esa-20240910/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

// --- fake ESA API -----------------------------------------------------------
//
// fakeESA stands in for the ESA SDK so the record logic can be exercised
// without a live Alibaba Cloud account. It records every request and returns
// scripted responses, which is what makes the failure paths below reachable.

type fakeESA struct {
	mu sync.Mutex

	sites       []esa.ListSitesResponseBodySites
	siteQueried []string
	siteErr     error

	// pages is keyed by 1-based page number for ListRecords calls without a
	// record-name filter (the GetRecords path). Calls that do filter by name
	// use matches instead.
	pages   map[int32][]*esa.ListRecordsResponseBodyRecords
	matches []*esa.ListRecordsResponseBodyRecords
	listErr error

	created   []*esa.CreateRecordRequest
	createErr error

	deleted   []int64
	deleteErr map[int64]error
}

func (f *fakeESA) ListSites(req *esa.ListSitesRequest) (*esa.ListSitesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.siteErr != nil {
		return nil, f.siteErr
	}
	want := dara.StringValue(req.SiteName)
	f.siteQueried = append(f.siteQueried, want)
	out := &esa.ListSitesResponse{Body: &esa.ListSitesResponseBody{}}
	for _, s := range f.sites {
		if strings.EqualFold(dara.StringValue(s.SiteName), want) {
			out.Body.Sites = append(out.Body.Sites, &s)
		}
	}
	return out, nil
}

func (f *fakeESA) ListRecords(req *esa.ListRecordsRequest) (*esa.ListRecordsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	recs := f.matches
	if req.RecordName == nil {
		recs = f.pages[dara.Int32Value(req.PageNumber)]
	}
	body := &esa.ListRecordsResponseBody{Records: recs}
	if recs != nil {
		body.TotalCount = dara.Int32(int32(len(recs)))
	}
	return &esa.ListRecordsResponse{Body: body}, nil
}

func (f *fakeESA) CreateRecord(req *esa.CreateRecordRequest) (*esa.CreateRecordResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = append(f.created, req)
	return &esa.CreateRecordResponse{Body: &esa.CreateRecordResponseBody{}}, nil
}

func (f *fakeESA) DeleteRecord(req *esa.DeleteRecordRequest) (*esa.DeleteRecordResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := dara.Int64Value(req.RecordId)
	if err, ok := f.deleteErr[id]; ok && err != nil {
		return nil, err
	}
	f.deleted = append(f.deleted, id)
	return &esa.DeleteRecordResponse{Body: &esa.DeleteRecordResponseBody{}}, nil
}

// testProvider wires a fake into a provider, bypassing getClient, and pre-seeds
// the site cache so tests do not have to script ListSites for every zone.
func testProvider(f esaAPI) *ESAProvider {
	p := &ESAProvider{AccessKeyID: "ak", AccessKeySecret: "sk", client: f}
	p.sites.Store("example.com", int64(4242))
	return p
}

func txtRecord(id int64, name, value string) *esa.ListRecordsResponseBodyRecords {
	return &esa.ListRecordsResponseBodyRecords{
		RecordId:   dara.Int64(id),
		RecordName: dara.String(name),
		RecordType: dara.String("TXT"),
		Ttl:        dara.Int64(30),
		Data:       &esa.ListRecordsResponseBodyRecordsData{Value: dara.String(value)},
	}
}

func challenge(name, value string) libdns.Record {
	return libdns.RR{Name: name, Type: "TXT", Data: value}
}

// --- module surface ---------------------------------------------------------

// TestBothProvidersAreRegisteredDistinct guards the two Alibaba Cloud products
// against being conflated: `alidns` is 云解析 DNS (alidns.aliyuncs.com) and
// `esa` is 边缘安全加速 (esa.<region>.aliyuncs.com). They use different APIs,
// different auth scopes and different onboarding modes, but share one repo.
func TestBothProvidersAreRegisteredDistinct(t *testing.T) {
	registered := map[string]bool{}
	for _, mod := range caddy.GetModules("dns.providers") {
		registered[string(mod.ID)] = true
	}
	for _, want := range []string{"dns.providers.alidns", "dns.providers.esa"} {
		if !registered[want] {
			t.Errorf("module %s is not registered; got %v", want, registered)
		}
	}
}

// TestESASatisfiesFullLibDNSSurface guards a constraint that is invisible from
// the source alone: Caddy type-asserts the module against all four libdns
// interfaces before accepting a global `dns` block (caddytls/tls.go), and ECH
// needs Get+Set (caddytls/ech.go). Dropping either pair compiles fine and then
// breaks at config-load time. AliDNS is checked the same way below.
func TestESASatisfiesFullLibDNSSurface(t *testing.T) {
	var m caddy.Module = &ESA{}
	if _, ok := m.(interface {
		libdns.RecordAppender
		libdns.RecordDeleter
		libdns.RecordGetter
		libdns.RecordSetter
	}); !ok {
		t.Error("ESA does not implement all four libdns interfaces; a global `dns` block would be rejected at load time")
	}
	if _, ok := m.(caddy.Provisioner); !ok {
		t.Error("ESA no longer implements caddy.Provisioner")
	}
	if _, ok := m.(caddy.Validator); !ok {
		t.Error("ESA no longer implements caddy.Validator")
	}
	if _, ok := m.(caddyfile.Unmarshaler); !ok {
		t.Error("ESA no longer implements caddyfile.Unmarshaler")
	}
}

// TestESARegistersExactlyOneModuleName pins the module surface. An earlier
// revision also registered `dns.providers.aliesa` as an "alias", justified as
// backwards compatibility — but the module had never been released, so there
// was nothing to stay compatible with. One name, one way to configure it.
func TestESARegistersExactlyOneModuleName(t *testing.T) {
	var names []string
	for _, mod := range caddy.GetModules("dns.providers") {
		if id := string(mod.ID); strings.Contains(id, "esa") {
			names = append(names, id)
		}
	}
	sort.Strings(names)

	want := []string{"dns.providers.esa"}
	if len(names) != len(want) || (len(names) == 1 && names[0] != want[0]) {
		t.Errorf("registered ESA module names = %v, want %v", names, want)
	}
}

// --- configuration ----------------------------------------------------------

func TestESAUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name          string
		caddyfile     string
		expectError   bool
		expectedKey   string
		expectedSec   string
		expectedToken string
		expectedRgn   string
	}{
		{
			name: "block format with access keys",
			caddyfile: `esa {
				access_key_id "test_key_id"
				access_key_secret "test_key_secret"
			}`,
			expectedKey: "test_key_id",
			expectedSec: "test_key_secret",
		},
		{
			name: "block format with optional security_token",
			caddyfile: `esa {
				access_key_id "test_key_id"
				access_key_secret "test_key_secret"
				security_token "test_token"
			}`,
			expectedKey:   "test_key_id",
			expectedSec:   "test_key_secret",
			expectedToken: "test_token",
		},
		{
			name: "block format with optional region_id",
			caddyfile: `esa {
				access_key_id "test_key_id"
				access_key_secret "test_key_secret"
				region_id "ap-southeast-1"
			}`,
			expectedKey: "test_key_id",
			expectedSec: "test_key_secret",
			expectedRgn: "ap-southeast-1",
		},
		{
			name:        "shorthand single line format",
			caddyfile:   `esa my_ak my_secret`,
			expectedKey: "my_ak",
			expectedSec: "my_secret",
		},
		{
			name: "missing access key secret",
			caddyfile: `esa {
				access_key_id "test_key_id"
			}`,
			expectError: true,
		},
		{
			name: "missing access key id",
			caddyfile: `esa {
				access_key_secret "test_key_secret"
			}`,
			expectError: true,
		},
		{
			name:        "unrecognized subdirective",
			caddyfile:   `esa { invalid_key "value" }`,
			expectError: true,
		},
		{
			name:        "shorthand with too many args",
			caddyfile:   `esa ak sk extra`,
			expectError: true,
		},
		{
			name:        "shorthand with only one arg",
			caddyfile:   `esa ak`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.caddyfile)
			provider := &ESA{}
			err := provider.UnmarshalCaddyfile(d)
			if (err != nil) != tt.expectError {
				t.Fatalf("UnmarshalCaddyfile() error = %v, expectError = %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}
			if provider.AccessKeyID != tt.expectedKey {
				t.Errorf("AccessKeyID = %v, want %v", provider.AccessKeyID, tt.expectedKey)
			}
			if provider.AccessKeySecret != tt.expectedSec {
				t.Errorf("AccessKeySecret = %v, want %v", provider.AccessKeySecret, tt.expectedSec)
			}
			if tt.expectedToken != "" && provider.SecurityToken != tt.expectedToken {
				t.Errorf("SecurityToken = %v, want %v", provider.SecurityToken, tt.expectedToken)
			}
			if provider.RegionID != tt.expectedRgn {
				t.Errorf("RegionID = %v, want %v", provider.RegionID, tt.expectedRgn)
			}
		})
	}
}

func TestESAProvisionResolvesPlaceholders(t *testing.T) {
	t.Setenv("ESA_TEST_AK", "resolved_ak")
	t.Setenv("ESA_TEST_SK", "resolved_sk")
	t.Setenv("ESA_TEST_TOKEN", "resolved_token")
	t.Setenv("ESA_TEST_REGION", "ap-southeast-1")

	esa := &ESA{ESAProvider: &ESAProvider{
		AccessKeyID:     "{env.ESA_TEST_AK}",
		AccessKeySecret: "{env.ESA_TEST_SK}",
		SecurityToken:   "{env.ESA_TEST_TOKEN}",
		RegionID:        "{env.ESA_TEST_REGION}",
	}}
	if err := esa.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if err := esa.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if esa.AccessKeyID != "resolved_ak" {
		t.Errorf("AccessKeyID = %q, want resolved_ak", esa.AccessKeyID)
	}
	if esa.AccessKeySecret != "resolved_sk" {
		t.Errorf("AccessKeySecret = %q, want resolved_sk", esa.AccessKeySecret)
	}
	if esa.SecurityToken != "resolved_token" {
		t.Errorf("SecurityToken = %q, want resolved_token", esa.SecurityToken)
	}
	if esa.RegionID != "ap-southeast-1" {
		t.Errorf("RegionID = %q, want ap-southeast-1", esa.RegionID)
	}
}

func TestESAProvisionAllowsNilProvider(t *testing.T) {
	// Caddyfile parsing in tests and JSON loading can both reach a nil provider.
	esa := &ESA{}
	if err := esa.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if esa.ESAProvider == nil {
		t.Fatal("Provision() left ESAProvider nil")
	}
}

// An incomplete key set must fail at config load. Without this, a JSON config
// with only an access_key_id loads fine and then fails a month later, during
// the first certificate issuance, buried in the ACME logs.
func TestESAValidateRequiresBothKeys(t *testing.T) {
	tests := []struct {
		name string
		ak   string
		sk   string
	}{
		{"both empty", "", ""},
		{"missing secret", "ak", ""},
		{"missing id", "", "sk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			esa := &ESA{ESAProvider: &ESAProvider{AccessKeyID: tt.ak, AccessKeySecret: tt.sk}}
			if err := esa.Validate(); err == nil {
				t.Fatal("Validate() = nil, want error")
			}
		})
	}

	esa := &ESA{ESAProvider: &ESAProvider{AccessKeyID: "ak", AccessKeySecret: "sk"}}
	if err := esa.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// --- pure helpers -----------------------------------------------------------

func TestSiteCandidates(t *testing.T) {
	tests := []struct {
		zone string
		want []string
	}{
		{"example.com.", []string{"example.com", "com"}},
		{"example.com", []string{"example.com", "com"}},
		{"EXAMPLE.COM.", []string{"example.com", "com"}},
		{".example.com.", []string{"example.com", "com"}},
		{"a.b.example.com.", []string{"a.b.example.com", "b.example.com", "example.com", "com"}},
		{"localhost", []string{"localhost"}},
		{"", nil},
	}
	for _, tt := range tests {
		got := siteCandidates(tt.zone)
		if len(got) != len(tt.want) {
			t.Errorf("siteCandidates(%q) = %v, want %v", tt.zone, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("siteCandidates(%q) = %v, want %v", tt.zone, got, tt.want)
				break
			}
		}
	}
}

func TestFQDN(t *testing.T) {
	tests := []struct {
		zone string
		name string
		want string
	}{
		// certmagic always passes the SOA-derived zone as an FQDN.
		{"example.com.", "_acme-challenge", "_acme-challenge.example.com"},
		{"example.com", "_acme-challenge", "_acme-challenge.example.com"},
		{"example.com.", "_acme-challenge.sub", "_acme-challenge.sub.example.com"},
		// Zone apex: ESA rejects an empty RecordName, so spell out the zone.
		{"example.com.", "@", "example.com"},
		{"example.com.", "", "example.com"},
		{"sub.example.com.", "@", "sub.example.com"},
		// Already absolute.
		{"example.com.", "_acme-challenge.example.com.", "_acme-challenge.example.com"},
	}
	for _, tt := range tests {
		if got := fqdn(tt.zone, tt.name); got != tt.want {
			t.Errorf("fqdn(%q, %q) = %q, want %q", tt.zone, tt.name, got, tt.want)
		}
	}
}

// TestAsRecord covers the libdns contract that methods return concrete
// RR-type structs: certmagic type-asserts nothing directly, but a caller that
// gets an opaque RR back cannot reliably compare or reuse the record, and the
// delete path round-trips the append result.
func TestAsRecord(t *testing.T) {
	txt := asRecord(libdns.RR{Name: "_acme-challenge", Type: "TXT", TTL: 60 * time.Second, Data: "token"})
	parsed, ok := txt.(libdns.TXT)
	if !ok {
		t.Fatalf("asRecord(TXT) returned %T, want libdns.TXT", txt)
	}
	if parsed.Text != "token" {
		t.Errorf("Text = %q, want token", parsed.Text)
	}
	if parsed.Name != "_acme-challenge" {
		t.Errorf("Name = %q, want _acme-challenge", parsed.Name)
	}

	addr := asRecord(libdns.RR{Name: "@", Type: "A", Data: "1.2.3.4"})
	if _, ok := addr.(libdns.Address); !ok {
		t.Errorf("asRecord(A) returned %T, want libdns.Address", addr)
	}

	// Types libdns does not model must fall back to the opaque RR, not error.
	unknown := asRecord(libdns.RR{Name: "@", Type: "CAA", Data: `0 issue "letsencrypt.org"`})
	if _, ok := unknown.(libdns.CAA); !ok {
		t.Errorf("asRecord(CAA) returned %T, want libdns.CAA", unknown)
	}
}

// --- getClient --------------------------------------------------------------

// TestGetClientConcurrent guards the lazy client init. certmagic presents and
// cleans up records from independent goroutines (a wildcard and an apex
// certificate share the _acme-challenge name), so p.client must never be read
// outside the mutex. Run with -race: the previous double-checked read tripped it.
func TestGetClientConcurrent(t *testing.T) {
	p := &ESAProvider{AccessKeyID: "ak", AccessKeySecret: "sk"}

	var wg sync.WaitGroup
	clients := make([]esaAPI, 16)
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client, err := p.getClient()
			if err != nil {
				t.Errorf("getClient() error = %v", err)
				return
			}
			clients[i] = client
		}(i)
	}
	wg.Wait()

	for i, client := range clients {
		if client != clients[0] {
			t.Fatalf("goroutine %d got a different client instance", i)
		}
	}
}

func TestGetClientRequiresCredentials(t *testing.T) {
	for _, p := range []*ESAProvider{{}, {AccessKeyID: "ak"}, {AccessKeySecret: "sk"}} {
		if _, err := p.getClient(); err == nil {
			t.Errorf("getClient() with %q/%q = nil error, want error", p.AccessKeyID, p.AccessKeySecret)
		}
	}
}

// --- getSiteID --------------------------------------------------------------

// A wrong AccessKey or a missing RAM policy must not be reported as a missing
// domain, or users go hunting for a domain problem that does not exist.
func TestGetSiteIDSurfacesAPIError(t *testing.T) {
	p := &ESAProvider{client: &fakeESA{siteErr: errors.New("InvalidAccessKeyId.NotFound")}}

	_, err := p.getSiteID(p.client, "example.com.")
	if err == nil {
		t.Fatal("getSiteID() = nil error, want the ListSites failure surfaced")
	}
	if !strings.Contains(err.Error(), "InvalidAccessKeyId.NotFound") {
		t.Errorf("error = %v, want it to wrap the API error", err)
	}
	if strings.Contains(err.Error(), "no ESA site found") {
		t.Errorf("error = %v, must not masquerade as a missing site", err)
	}
}

func TestGetSiteIDWalksLabelsAndCaches(t *testing.T) {
	f := &fakeESA{sites: []esa.ListSitesResponseBodySites{
		{SiteId: dara.Int64(99), SiteName: dara.String("example.com")},
	}}
	p := &ESAProvider{client: f}

	// The zone is an FQDN with a trailing dot, as certmagic derives it from SOA.
	id, err := p.getSiteID(f, "a.b.example.com.")
	if err != nil {
		t.Fatalf("getSiteID() error = %v", err)
	}
	if id != 99 {
		t.Errorf("siteID = %d, want 99", id)
	}
	want := []string{"a.b.example.com", "b.example.com", "example.com"}
	if strings.Join(f.siteQueried, ",") != strings.Join(want, ",") {
		t.Errorf("ListSites called with %v, want %v", f.siteQueried, want)
	}

	// Second call must be served from cache under the original zone key.
	f.siteQueried = nil
	if _, err := p.getSiteID(f, "a.b.example.com."); err != nil {
		t.Fatalf("getSiteID() error = %v", err)
	}
	if len(f.siteQueried) != 0 {
		t.Errorf("ListSites called %v on a cache hit, want no calls", f.siteQueried)
	}
}

func TestGetSiteIDNotFoundIsActionable(t *testing.T) {
	p := &ESAProvider{client: &fakeESA{}}

	_, err := p.getSiteID(p.client, "nothere.example.")
	if err == nil {
		t.Fatal("getSiteID() = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "onboard") {
		t.Errorf("error = %v, want it to mention onboarding the domain", err)
	}
}

func TestGetSiteIDIgnoresForeignSitesInResponse(t *testing.T) {
	// ESA's exact-match filter should already guarantee this, but a stale or
	// mis-filtered response must not resolve to the wrong site.
	f := &fakeESA{sites: []esa.ListSitesResponseBodySites{
		{SiteId: dara.Int64(1), SiteName: dara.String("other.com")},
	}}
	p := &ESAProvider{client: f}

	if _, err := p.getSiteID(f, "example.com."); err == nil {
		t.Fatal("getSiteID() accepted a non-matching site name")
	}
}

// --- AppendRecords ----------------------------------------------------------

func TestAppendRecordsSendsFullyQualifiedName(t *testing.T) {
	f := &fakeESA{}
	p := testProvider(f)

	added, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", "token"),
	})
	if err != nil {
		t.Fatalf("AppendRecords() error = %v", err)
	}
	if len(added) != 1 {
		t.Fatalf("got %d records, want 1", len(added))
	}
	// certmagic requires exactly one record back, as a concrete type, so it can
	// re-derive the same RR when cleaning up.
	if _, ok := added[0].(libdns.TXT); !ok {
		t.Errorf("AppendRecords returned %T, want libdns.TXT", added[0])
	}

	if len(f.created) != 1 {
		t.Fatalf("CreateRecord called %d times, want 1", len(f.created))
	}
	req := f.created[0]
	if got := dara.StringValue(req.RecordName); got != "_acme-challenge.example.com" {
		t.Errorf("RecordName = %q, want _acme-challenge.example.com", got)
	}
	if got := dara.StringValue(req.Type); got != "TXT" {
		t.Errorf("Type = %q, want TXT", got)
	}
	if got := dara.StringValue(req.Data.Value); got != "token" {
		t.Errorf("Data.Value = %q, want token", got)
	}
	if got := dara.Int32Value(req.Ttl); got != defaultTTL {
		t.Errorf("Ttl = %d, want the %ds default for an unset TTL", got, defaultTTL)
	}
	if got := dara.Int64Value(req.SiteId); got != 4242 {
		t.Errorf("SiteId = %d, want 4242", got)
	}
}

func TestAppendRecordsKeepsRequestedTTL(t *testing.T) {
	f := &fakeESA{}
	p := testProvider(f)

	rec := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "t", TTL: 5 * time.Minute}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{rec}); err != nil {
		t.Fatalf("AppendRecords() error = %v", err)
	}
	if got := dara.Int32Value(f.created[0].Ttl); got != 300 {
		t.Errorf("Ttl = %d, want 300", got)
	}
}

// A hand-edited or absurd dns_ttl must not overflow int32 into a negative TTL.
func TestAppendRecordsClampsAbsurdTTL(t *testing.T) {
	f := &fakeESA{}
	p := testProvider(f)

	rec := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "t", TTL: time.Duration(1<<62 - 1)}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{rec}); err != nil {
		t.Fatalf("AppendRecords() error = %v", err)
	}
	if got := dara.Int32Value(f.created[0].Ttl); got != defaultTTL {
		t.Errorf("Ttl = %d, want the %ds default", got, defaultTTL)
	}
}

func TestAppendRecordsPropagatesError(t *testing.T) {
	p := testProvider(&fakeESA{createErr: errors.New("Record.RecordNameConflictWithSameRecordType")})

	_, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", "token"),
	})
	if err == nil {
		t.Fatal("AppendRecords() = nil error, want the API failure surfaced")
	}
}

func TestAppendRecordsHandlesZoneApex(t *testing.T) {
	f := &fakeESA{}
	p := testProvider(f)

	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("@", "token"),
	}); err != nil {
		t.Fatalf("AppendRecords() error = %v", err)
	}
	// ESA rejects an empty RecordName, so the apex must be spelled out.
	if got := dara.StringValue(f.created[0].RecordName); got != "example.com" {
		t.Errorf("RecordName = %q, want example.com", got)
	}
}

// --- DeleteRecords ----------------------------------------------------------
//
// These four tests exist because the previous implementation discarded both API
// errors with a `continue` / `delErr == nil`. certmagic reads a nil error as
// "challenge cleaned up" and logs success, so a leaked _acme-challenge TXT
// record breaks the *next* issuance with RecordNameConflictWithSameRecordType —
// a failure whose symptom sits hours away from its cause.

func TestDeleteRecordsPropagatesListError(t *testing.T) {
	p := testProvider(&fakeESA{listErr: errors.New("Throttling.User")})

	_, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", "token"),
	})
	if err == nil {
		t.Fatal("DeleteRecords() = nil error, want the ListRecords failure surfaced")
	}
	if !strings.Contains(err.Error(), "Throttling.User") {
		t.Errorf("error = %v, want it to wrap the API error", err)
	}
}

func TestDeleteRecordsPropagatesDeleteError(t *testing.T) {
	p := testProvider(&fakeESA{
		matches:   []*esa.ListRecordsResponseBodyRecords{txtRecord(7, "_acme-challenge.example.com", "token")},
		deleteErr: map[int64]error{7: errors.New("Record.NotFound")},
	})

	_, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", "token"),
	})
	if err == nil {
		t.Fatal("DeleteRecords() = nil error, want the DeleteRecord failure surfaced")
	}
	if !strings.Contains(err.Error(), "Record.NotFound") {
		t.Errorf("error = %v, want it to wrap the API error", err)
	}
}

// Only the record whose value matches may be deleted: a wildcard and an apex
// challenge live at the same name with different tokens.
func TestDeleteRecordsMatchesValueExactly(t *testing.T) {
	f := &fakeESA{matches: []*esa.ListRecordsResponseBodyRecords{
		txtRecord(1, "_acme-challenge.example.com", "token-a"),
		txtRecord(2, "_acme-challenge.example.com", "token-b"),
	}}
	p := testProvider(f)

	deleted, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", "token-a"),
	})
	if err != nil {
		t.Fatalf("DeleteRecords() error = %v", err)
	}
	if len(deleted) != 1 {
		t.Errorf("deleted %d records, want 1", len(deleted))
	}
	if len(f.deleted) != 1 || f.deleted[0] != 1 {
		t.Errorf("deleted record IDs = %v, want [1]", f.deleted)
	}
}

// Quoted and unquoted values are different records. Matching them loosely would
// let a delete request remove a record the caller never named.
func TestDeleteRecordsDoesNotLooselyMatchValues(t *testing.T) {
	f := &fakeESA{matches: []*esa.ListRecordsResponseBodyRecords{
		txtRecord(1, "_acme-challenge.example.com", "token"),
	}}
	p := testProvider(f)

	deleted, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", `"token"`),
	})
	if err != nil {
		t.Fatalf("DeleteRecords() error = %v", err)
	}
	if len(deleted) != 0 || len(f.deleted) != 0 {
		t.Errorf("deleted %v, want nothing: \"token\" is not the record `token`", f.deleted)
	}
}

// libdns allows an empty Data to mean "delete every record at this name".
func TestDeleteRecordsEmptyDataDeletesAll(t *testing.T) {
	f := &fakeESA{matches: []*esa.ListRecordsResponseBodyRecords{
		txtRecord(1, "_acme-challenge.example.com", "token-a"),
		txtRecord(2, "_acme-challenge.example.com", "token-b"),
	}}
	p := testProvider(f)

	if _, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", ""),
	}); err != nil {
		t.Fatalf("DeleteRecords() error = %v", err)
	}
	if len(f.deleted) != 2 {
		t.Errorf("deleted %v, want both records", f.deleted)
	}
}

// A record that is already gone must be a silent no-op, per the libdns contract.
func TestDeleteRecordsMissingIsNotAnError(t *testing.T) {
	p := testProvider(&fakeESA{})

	deleted, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", "gone"),
	})
	if err != nil {
		t.Fatalf("DeleteRecords() error = %v, want nil", err)
	}
	if len(deleted) != 0 {
		t.Errorf("deleted = %v, want none", deleted)
	}
}

// --- GetRecords -------------------------------------------------------------

// ESA may omit TotalCount. Trusting it silently returned only page 1.
func TestGetRecordsPaginatesWithoutTotalCount(t *testing.T) {
	page1 := make([]*esa.ListRecordsResponseBodyRecords, maxPageSize)
	for i := range page1 {
		page1[i] = txtRecord(int64(i+1), "_acme-challenge.example.com", fmt.Sprintf("v%d", i))
	}
	page2 := []*esa.ListRecordsResponseBodyRecords{
		txtRecord(9001, "last.example.com", "final"),
	}

	p := testProvider(&fakeESA{pages: map[int32][]*esa.ListRecordsResponseBodyRecords{
		1: page1,
		2: page2,
	}})

	records, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error = %v", err)
	}
	if len(records) != maxPageSize+1 {
		t.Errorf("got %d records, want %d (page 1 + page 2)", len(records), maxPageSize+1)
	}
}

func TestGetRecordsStopsOnShortPage(t *testing.T) {
	p := testProvider(&fakeESA{pages: map[int32][]*esa.ListRecordsResponseBodyRecords{
		1: {txtRecord(1, "a.example.com", "one")},
	}})

	records, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error = %v", err)
	}
	if len(records) != 1 {
		t.Errorf("got %d records, want 1", len(records))
	}
}

func TestGetRecordsPropagatesError(t *testing.T) {
	p := testProvider(&fakeESA{listErr: errors.New("Throttling.User")})

	if _, err := p.GetRecords(context.Background(), "example.com."); err == nil {
		t.Fatal("GetRecords() = nil error, want the API failure surfaced")
	}
}

func TestGetRecordsReturnsZoneRelativeNames(t *testing.T) {
	p := testProvider(&fakeESA{pages: map[int32][]*esa.ListRecordsResponseBodyRecords{
		1: {
			txtRecord(1, "_acme-challenge.example.com", "token"),
			txtRecord(2, "example.com", "apex"),
			txtRecord(3, "sub.example.com", "sub"),
		},
	}})

	records, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error = %v", err)
	}
	wantNames := map[string]bool{"_acme-challenge": true, "@": true, "sub": true}
	for _, rec := range records {
		name := rec.RR().Name
		if !wantNames[name] {
			t.Errorf("record name = %q, want one of %v", name, wantNames)
		}
		delete(wantNames, name)
	}
	if len(wantNames) != 0 {
		t.Errorf("missing records for %v", wantNames)
	}
}

// --- SetRecords -------------------------------------------------------------

// Getting the RRset scope wrong deletes unrelated records from a live zone.
func TestSetRecordsOnlyTouchesTheNamedRRset(t *testing.T) {
	f := &fakeESA{pages: map[int32][]*esa.ListRecordsResponseBodyRecords{
		1: {
			txtRecord(1, "_acme-challenge.example.com", "old-token"),
			txtRecord(2, "example.com", "v=spf1 -all"),
			txtRecord(3, "sub.example.com", "unrelated"),
		},
	}}
	f.matches = f.pages[1]
	p := testProvider(f)

	if _, err := p.SetRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", "new-token"),
	}); err != nil {
		t.Fatalf("SetRecords() error = %v", err)
	}

	if len(f.deleted) != 1 || f.deleted[0] != 1 {
		t.Errorf("deleted %v, want only record 1 (the stale challenge)", f.deleted)
	}
	if len(f.created) != 1 || dara.StringValue(f.created[0].Data.Value) != "new-token" {
		t.Errorf("created %v, want only the new challenge record", f.created)
	}
}

func TestSetRecordsCreatesWhenNothingMatches(t *testing.T) {
	f := &fakeESA{pages: map[int32][]*esa.ListRecordsResponseBodyRecords{1: {}}}
	p := testProvider(f)

	if _, err := p.SetRecords(context.Background(), "example.com.", []libdns.Record{
		challenge("_acme-challenge", "new-token"),
	}); err != nil {
		t.Fatalf("SetRecords() error = %v", err)
	}
	if len(f.deleted) != 0 {
		t.Errorf("deleted %v, want nothing", f.deleted)
	}
	if len(f.created) != 1 {
		t.Errorf("created %d records, want 1", len(f.created))
	}
}

// --- context cancellation ---------------------------------------------------

// libdns requires every method to honour cancellation, and certmagic cancels on
// propagation timeout. The ESA SDK's non-WithOptions calls take no context of
// their own, so the check has to be ours.
func TestMethodsHonourCancelledContext(t *testing.T) {
	p := testProvider(&fakeESA{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	recs := []libdns.Record{challenge("_acme-challenge", "t")}

	if _, err := p.AppendRecords(ctx, "example.com.", recs); err == nil {
		t.Error("AppendRecords() with a cancelled context = nil error, want error")
	}
	if _, err := p.DeleteRecords(ctx, "example.com.", recs); err == nil {
		t.Error("DeleteRecords() with a cancelled context = nil error, want error")
	}
	if _, err := p.GetRecords(ctx, "example.com."); err == nil {
		t.Error("GetRecords() with a cancelled context = nil error, want error")
	}
	if _, err := p.SetRecords(ctx, "example.com.", recs); err == nil {
		t.Error("SetRecords() with a cancelled context = nil error, want error")
	}
}
