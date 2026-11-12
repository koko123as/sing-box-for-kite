package libbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	mihomoGeodata "github.com/metacubex/mihomo/component/geodata"
	mihomoRouter "github.com/metacubex/mihomo/component/geodata/router"
	"github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/proto"
)

// Geo data (GeoIP, GeoSite, MMDB, ASN) shared by Xray and mihomo, modelled on
// FlClash: the app ships a copy in its assets, extracts it on first use and
// can replace each file from its own URL. All four live in mihomo's home
// directory, which mihomo searches by case-insensitive name; Xray is pointed
// at the same directory through xray.location.asset and reads the lower-case
// geoip.dat / geosite.dat written here.

const (
	GeoResourceGeoIP   = "geoip"
	GeoResourceGeoSite = "geosite"
	GeoResourceMMDB    = "mmdb"
	GeoResourceASN     = "asn"

	geoDownloadLimit   = 96 * 1024 * 1024
	geoDownloadTimeout = 5 * time.Minute
)

type geoResourceSpec struct {
	file       string
	defaultURL string
	verify     func([]byte) error
}

// Default URLs are FlClash's defaultGeoXUrl (MetaCubeX/meta-rules-dat).
var geoResourceSpecs = map[string]geoResourceSpec{
	GeoResourceGeoIP: {
		file:       "geoip.dat",
		defaultURL: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
		verify:     verifyGeoIPData,
	},
	GeoResourceGeoSite: {
		file:       "geosite.dat",
		defaultURL: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
		verify:     verifyGeoSiteData,
	},
	GeoResourceMMDB: {
		file:       "geoip.metadb",
		defaultURL: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
		verify:     verifyMMDBData,
	},
	GeoResourceASN: {
		file:       "ASN.mmdb",
		defaultURL: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
		verify:     verifyMMDBData,
	},
}

var geoResourceLocks sync.Map

// GeoDataDir is the shared geo directory under the working directory.
func GeoDataDir() string {
	return coreAssetDir(sWorkingPath, CoreMihomo)
}

// GeoResourceFileName returns the file a resource is stored as, or "".
func GeoResourceFileName(name string) string {
	return geoResourceSpecs[name].file
}

// GeoResourceDefaultURL returns the URL a resource updates from by default.
func GeoResourceDefaultURL(name string) string {
	return geoResourceSpecs[name].defaultURL
}

// GeoUpdateResult describes the file after an update. Skipped means the
// download matched the installed file, which was left untouched.
type GeoUpdateResult struct {
	Size    int64
	Sha256  string
	Skipped bool
}

// UpdateGeoResource downloads one resource into dir, checks that it parses as
// that kind of database and replaces the installed file atomically. Any
// failure leaves the previous file as it was.
func UpdateGeoResource(dir string, name string, link string) (*GeoUpdateResult, error) {
	spec, ok := geoResourceSpecs[name]
	if !ok {
		return nil, fmt.Errorf("unknown geo resource: %s", name)
	}
	if strings.TrimSpace(link) == "" {
		link = spec.defaultURL
	}
	lock, _ := geoResourceLocks.LoadOrStore(name, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	data, err := downloadGeoResource(link)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", spec.file, err)
	}
	return installGeoResource(dir, name, data)
}

// VerifyGeoResource checks an installed file the same way a download is checked.
func VerifyGeoResource(dir string, name string) error {
	spec, ok := geoResourceSpecs[name]
	if !ok {
		return fmt.Errorf("unknown geo resource: %s", name)
	}
	data, err := os.ReadFile(filepath.Join(dir, spec.file))
	if err != nil {
		return err
	}
	return spec.verify(data)
}

func installGeoResource(dir string, name string, data []byte) (*GeoUpdateResult, error) {
	spec := geoResourceSpecs[name]
	if len(data) == 0 {
		return nil, fmt.Errorf("%s: empty file", spec.file)
	}
	if err := spec.verify(data); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", spec.file, err)
	}
	sum := sha256.Sum256(data)
	result := &GeoUpdateResult{Size: int64(len(data)), Sha256: hex.EncodeToString(sum[:])}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	target := filepath.Join(dir, spec.file)
	if current, err := os.ReadFile(target); err == nil {
		if currentSum := sha256.Sum256(current); currentSum == sum {
			result.Skipped = true
			return result, nil
		}
	}
	if err := writeFileAtomic(target, data); err != nil {
		return nil, err
	}
	removeGeoNameVariants(dir, spec.file)
	switch name {
	case GeoResourceGeoIP:
		mihomoGeodata.ClearGeoIPCache()
	case GeoResourceGeoSite:
		mihomoGeodata.ClearGeoSiteCache()
	}
	return result, nil
}

func downloadGeoResource(link string) ([]byte, error) {
	target, err := url.Parse(link)
	if err != nil || target == nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("invalid HTTP or HTTPS address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), geoDownloadTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP request")
	}
	if target.User != nil {
		password, _ := target.User.Password()
		request.SetBasicAuth(target.User.Username(), password)
	}
	client := NewHTTPClient().(*httpClient)
	defer client.Close()
	client.ModernTLS()
	client.client.Timeout = geoDownloadTimeout
	response, err := client.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", response.Status)
	}
	if response.ContentLength > geoDownloadLimit {
		return nil, fmt.Errorf("file exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, geoDownloadLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > geoDownloadLimit {
		return nil, fmt.Errorf("file exceeds size limit")
	}
	return data, nil
}

// writeFileAtomic writes beside the target and renames over it, so a reader
// (or a core that has the file mapped) sees either the old or the new file.
func writeFileAtomic(target string, data []byte) error {
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	temp := target + ".tmp-" + hex.EncodeToString(suffix)
	file, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temp, target)
	}
	if err != nil {
		_ = os.Remove(temp)
	}
	return err
}

// mihomo may have downloaded GeoIP.dat / GeoSite.dat under its own spelling;
// on a case-sensitive file system that copy would shadow ours for mihomo.
func removeGeoNameVariants(dir string, file string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	target, err := os.Stat(filepath.Join(dir, file))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == file || !strings.EqualFold(entry.Name(), file) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if info, err := os.Stat(path); err == nil && !os.SameFile(info, target) {
			_ = os.Remove(path)
		}
	}
}

func verifyGeoIPData(data []byte) error {
	var list mihomoRouter.GeoIPList
	if err := proto.Unmarshal(data, &list); err != nil {
		return err
	}
	for _, entry := range list.Entry {
		if entry.CountryCode == "" {
			continue
		}
		for _, cidr := range entry.Cidr {
			if len(cidr.Ip) == 4 || len(cidr.Ip) == 16 {
				return nil
			}
		}
	}
	return fmt.Errorf("no GeoIP entries")
}

func verifyGeoSiteData(data []byte) error {
	var list mihomoRouter.GeoSiteList
	if err := proto.Unmarshal(data, &list); err != nil {
		return err
	}
	for _, entry := range list.Entry {
		if entry.CountryCode == "" {
			continue
		}
		for _, domain := range entry.Domain {
			if domain.Value != "" {
				return nil
			}
		}
	}
	return fmt.Errorf("no GeoSite entries")
}

func verifyMMDBData(data []byte) error {
	reader, err := maxminddb.FromBytes(data)
	if err != nil {
		return err
	}
	return reader.Close()
}
