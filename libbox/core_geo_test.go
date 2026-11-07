package libbox

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	mihomoRouter "github.com/metacubex/mihomo/component/geodata/router"
	"google.golang.org/protobuf/proto"
)

func testGeoIPData(t *testing.T, prefix uint32) []byte {
	t.Helper()
	data, err := proto.Marshal(&mihomoRouter.GeoIPList{Entry: []*mihomoRouter.GeoIP{{
		CountryCode: "CN",
		Cidr:        []*mihomoRouter.CIDR{{Ip: []byte{1, 0, 1, 0}, Prefix: prefix}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testGeoSiteData(t *testing.T) []byte {
	t.Helper()
	data, err := proto.Marshal(&mihomoRouter.GeoSiteList{Entry: []*mihomoRouter.GeoSite{{
		CountryCode: "CN",
		Domain:      []*mihomoRouter.Domain{{Type: mihomoRouter.Domain_Full, Value: "example.cn"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCoreGeoResourceSpecs(t *testing.T) {
	for name, file := range map[string]string{
		GeoResourceGeoIP: "geoip.dat", GeoResourceGeoSite: "geosite.dat",
		GeoResourceMMDB: "geoip.metadb", GeoResourceASN: "ASN.mmdb",
	} {
		if GeoResourceFileName(name) != file {
			t.Errorf("%s file = %q, want %q", name, GeoResourceFileName(name), file)
		}
		if GeoResourceDefaultURL(name) == "" {
			t.Errorf("%s has no default URL", name)
		}
	}
	if GeoResourceFileName("nope") != "" {
		t.Error("unknown resource has a file name")
	}
}

func TestCoreGeoVerifyRejectsWrongData(t *testing.T) {
	html := []byte("<!DOCTYPE html><html><body>rate limited</body></html>")
	for _, name := range []string{GeoResourceGeoIP, GeoResourceGeoSite, GeoResourceMMDB, GeoResourceASN} {
		if err := geoResourceSpecs[name].verify(html); err == nil {
			t.Errorf("%s accepted an HTML page", name)
		}
	}
	if err := verifyGeoIPData(testGeoIPData(t, 24)); err != nil {
		t.Errorf("valid GeoIP rejected: %v", err)
	}
	if err := verifyGeoSiteData(testGeoSiteData(t)); err != nil {
		t.Errorf("valid GeoSite rejected: %v", err)
	}
	if err := verifyGeoIPData(nil); err == nil {
		t.Error("empty GeoIP accepted")
	}
}

func TestCoreGeoUpdateKeepsOldFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	old := testGeoIPData(t, 16)
	target := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(target, old, 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/error":
			w.WriteHeader(http.StatusBadGateway)
		case "/html":
			_, _ = w.Write([]byte("<html>not a database</html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	for _, path := range []string{"/error", "/html"} {
		if _, err := UpdateGeoResource(dir, GeoResourceGeoIP, server.URL+path); err == nil {
			t.Fatalf("%s: update succeeded", path)
		}
		current, err := os.ReadFile(target)
		if err != nil || !bytes.Equal(current, old) {
			t.Fatalf("%s: old file changed (err %v)", path, err)
		}
	}
	if _, err := UpdateGeoResource(dir, "nope", server.URL); err == nil {
		t.Fatal("unknown resource updated")
	}
	if _, err := UpdateGeoResource(dir, GeoResourceGeoIP, "ftp://example.com/geoip.dat"); err == nil {
		t.Fatal("non-HTTP address accepted")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestCoreGeoUpdateReplacesAndSkips(t *testing.T) {
	dir := t.TempDir()
	fresh := testGeoSiteData(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fresh)
	}))
	defer server.Close()
	// mihomo's own spelling of the file, as it downloads it.
	variant := filepath.Join(dir, "GeoSite.dat")
	if err := os.WriteFile(variant, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := UpdateGeoResource(dir, GeoResourceGeoSite, server.URL+"/geosite.dat")
	if err != nil {
		t.Fatal(err)
	}
	if result.Skipped || result.Size != int64(len(fresh)) || len(result.Sha256) != 64 {
		t.Fatalf("unexpected result: %+v", result)
	}
	current, err := os.ReadFile(filepath.Join(dir, "geosite.dat"))
	if err != nil || !bytes.Equal(current, fresh) {
		t.Fatalf("file not replaced (err %v)", err)
	}
	if err := VerifyGeoResource(dir, GeoResourceGeoSite); err != nil {
		t.Fatal(err)
	}
	// On a case-insensitive file system the variant is the same file.
	if info, err := os.Stat(variant); err == nil {
		target, _ := os.Stat(filepath.Join(dir, "geosite.dat"))
		if !os.SameFile(info, target) {
			t.Fatal("stale GeoSite.dat left beside geosite.dat")
		}
	}
	again, err := UpdateGeoResource(dir, GeoResourceGeoSite, server.URL+"/geosite.dat")
	if err != nil || !again.Skipped || again.Sha256 != result.Sha256 {
		t.Fatalf("unchanged download not skipped: %+v, %v", again, err)
	}
}
