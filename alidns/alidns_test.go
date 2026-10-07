package alidns

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	libdnsalidns "github.com/libdns/alidns"
	"github.com/libdns/libdns"
)

// ============================================================================
// AliDNS (云解析 DNS) — dns.providers.alidns
//
// The ESA tests above drive the ESA SDK through a fake. AliDNS is the opposite
// shape: this file only wraps github.com/libdns/alidns, so the testable surface
// is the Caddy plumbing (parsing, provisioning, validation), not the DNS calls
// themselves.
// ============================================================================

// --- AliDNS: module surface -------------------------------------------------

func TestAliDNSSatisfiesFullLibDNSSurface(t *testing.T) {
	var m caddy.Module = &Provider{}
	if _, ok := m.(interface {
		libdns.RecordAppender
		libdns.RecordDeleter
		libdns.RecordGetter
		libdns.RecordSetter
	}); !ok {
		t.Error("AliDNS does not implement all four libdns interfaces; a global `dns` block would be rejected at load time")
	}
	if _, ok := m.(caddy.Provisioner); !ok {
		t.Error("AliDNS no longer implements caddy.Provisioner")
	}
	if _, ok := m.(caddy.Validator); !ok {
		t.Error("AliDNS no longer implements caddy.Validator")
	}
	if _, ok := m.(caddyfile.Unmarshaler); !ok {
		t.Error("AliDNS no longer implements caddyfile.Unmarshaler")
	}
}

// --- AliDNS: configuration --------------------------------------------------

func TestAliDNSUnmarshalCaddyfile(t *testing.T) {
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
			caddyfile: `alidns {
				access_key_id "test_key_id"
				access_key_secret "test_key_secret"
			}`,
			expectedKey: "test_key_id",
			expectedSec: "test_key_secret",
		},
		{
			name: "block format with optional region_id",
			caddyfile: `alidns {
				access_key_id "test_key_id"
				access_key_secret "test_key_secret"
				region_id "ap-southeast-1"
			}`,
			expectedKey: "test_key_id",
			expectedSec: "test_key_secret",
			expectedRgn: "ap-southeast-1",
		},
		{
			name: "block format with optional security_token",
			caddyfile: `alidns {
				access_key_id "test_key_id"
				access_key_secret "test_key_secret"
				security_token "test_token"
			}`,
			expectedKey:   "test_key_id",
			expectedSec:   "test_key_secret",
			expectedToken: "test_token",
		},
		{
			name:        "all four directives",
			caddyfile:   `alidns { access_key_id "ak" access_key_secret "sk" region_id "cn-hangzhou" security_token "st" }`,
			expectedKey: "ak", expectedSec: "sk", expectedRgn: "cn-hangzhou", expectedToken: "st",
		},
		{
			// Unlike ESA, AliDNS has never accepted a positional form; the
			// shorthand belongs to the ESA provider only.
			name:        "shorthand is rejected",
			caddyfile:   `alidns ak sk`,
			expectError: true,
		},
		{
			name: "missing access key secret",
			caddyfile: `alidns {
				access_key_id "test_key_id"
			}`,
			expectError: true,
		},
		{
			name: "missing access key id",
			caddyfile: `alidns {
				access_key_secret "test_key_secret"
			}`,
			expectError: true,
		},
		{
			name:        "unrecognized subdirective",
			caddyfile:   `alidns { invalid_key "value" }`,
			expectError: true,
		},
		{
			// d.Args requires exactly one argument, so an over-specified
			// directive is a config error rather than a silent truncation.
			name:        "too many args for a directive",
			caddyfile:   `alidns { access_key_id "ak" "extra" access_key_secret "sk" }`,
			expectError: true,
		},
		{
			name:        "empty block",
			caddyfile:   `alidns { }`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.caddyfile)
			provider := &Provider{Provider: new(libdnsalidns.Provider)}
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
			if provider.RegionID != tt.expectedRgn {
				t.Errorf("RegionID = %v, want %v", provider.RegionID, tt.expectedRgn)
			}
			if tt.expectedToken != "" && provider.SecurityToken != tt.expectedToken {
				t.Errorf("SecurityToken = %v, want %v", provider.SecurityToken, tt.expectedToken)
			}
		})
	}
}

// TestAliDNSUnmarshalCaddyfileNilProvider pins that parsing never dereferences a
// nil embedded provider. Caddy always supplies one via CaddyModule().New, so
// this is defensive rather than a live crash — but the previous code panicked
// here, and a nil dereference is a much worse failure mode than an error.
func TestAliDNSUnmarshalCaddyfileNilProvider(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("UnmarshalCaddyfile() panicked: %v", r)
		}
	}()

	p := &Provider{}
	err := p.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`alidns {
		access_key_id "ak"
		access_key_secret "sk"
	}`))
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	if p.Provider == nil {
		t.Fatal("UnmarshalCaddyfile() left the embedded provider nil")
	}
	if p.AccessKeyID != "ak" {
		t.Errorf("AccessKeyID = %q, want ak", p.AccessKeyID)
	}
}

// Provision resolves {env.*} in every credential field. region_id used to be
// skipped, so `region_id "{env.X}"` reached the API as a literal placeholder.
func TestAliDNSProvisionResolvesPlaceholders(t *testing.T) {
	t.Setenv("ALI_TEST_AK", "resolved_ak")
	t.Setenv("ALI_TEST_SK", "resolved_sk")
	t.Setenv("ALI_TEST_TOKEN", "resolved_token")
	t.Setenv("ALI_TEST_REGION", "ap-southeast-1")

	p := &Provider{Provider: &libdnsalidns.Provider{
		CredentialInfo: libdnsalidns.CredentialInfo{
			AccessKeyID:     "{env.ALI_TEST_AK}",
			AccessKeySecret: "{env.ALI_TEST_SK}",
			SecurityToken:   "{env.ALI_TEST_TOKEN}",
			RegionID:        "{env.ALI_TEST_REGION}",
		},
	}}
	if err := p.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	for _, tc := range []struct{ name, got, want string }{
		{"AccessKeyID", p.AccessKeyID, "resolved_ak"},
		{"AccessKeySecret", p.AccessKeySecret, "resolved_sk"},
		{"SecurityToken", p.SecurityToken, "resolved_token"},
		{"RegionID", p.RegionID, "ap-southeast-1"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestAliDNSProvisionAllowsNilProvider(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Provision() panicked: %v", r)
		}
	}()

	p := &Provider{}
	if err := p.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if p.Provider == nil {
		t.Fatal("Provision() left the embedded provider nil")
	}
}

// An incomplete key set must fail at config load. Verified against a real
// binary: before this test existed, `caddy validate` accepted a JSON config
// carrying only access_key_id, and the failure surfaced a month later during
// certificate issuance instead.
func TestAliDNSValidateRequiresBothKeys(t *testing.T) {
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
			p := &Provider{Provider: &libdnsalidns.Provider{
				CredentialInfo: libdnsalidns.CredentialInfo{AccessKeyID: tt.ak, AccessKeySecret: tt.sk},
			}}
			if err := p.Validate(); err == nil {
				t.Fatal("Validate() = nil, want error")
			}
		})
	}

	p := &Provider{Provider: &libdnsalidns.Provider{
		CredentialInfo: libdnsalidns.CredentialInfo{AccessKeyID: "ak", AccessKeySecret: "sk"},
	}}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// TestAliDNSValidateNilProvider covers the JSON path where nothing ever set the
// embedded pointer.
func TestAliDNSValidateNilProvider(t *testing.T) {
	if err := (&Provider{}).Validate(); err == nil {
		t.Error("Validate() on a nil embedded provider = nil, want error")
	}
}
