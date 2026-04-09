package threat

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// GeoResolver resolves an IP address to a coarse geographic location.
type GeoResolver interface {
	Lookup(ip string) (GeoLocation, bool)
}

// GeoLocation is the normalized location context attached to a threat event.
type GeoLocation struct {
	CountryCode    string  `json:"country_code,omitempty"`
	Country        string  `json:"country,omitempty"`
	Region         string  `json:"region,omitempty"`
	City           string  `json:"city,omitempty"`
	Latitude       float64 `json:"latitude,omitempty"`
	Longitude      float64 `json:"longitude,omitempty"`
	HasCoordinates bool    `json:"-"`
}

func (g GeoLocation) label() string {
	parts := make([]string, 0, 3)
	if g.City != "" {
		parts = append(parts, g.City)
	}
	if g.Region != "" && !strings.EqualFold(g.Region, g.City) {
		parts = append(parts, g.Region)
	}
	switch {
	case g.Country != "":
		parts = append(parts, g.Country)
	case g.CountryCode != "":
		parts = append(parts, g.CountryCode)
	}
	if len(parts) == 0 {
		return "unknown location"
	}
	return strings.Join(parts, ", ")
}

func (g GeoLocation) countryKey() string {
	switch {
	case g.CountryCode != "":
		return strings.ToLower(strings.TrimSpace(g.CountryCode))
	case g.Country != "":
		return strings.ToLower(strings.TrimSpace(g.Country))
	default:
		return ""
	}
}

func (g GeoLocation) locationKey() string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(g.CountryCode)),
		strings.ToLower(strings.TrimSpace(g.Country)),
		strings.ToLower(strings.TrimSpace(g.Region)),
		strings.ToLower(strings.TrimSpace(g.City)),
	}
	hasValue := false
	for _, part := range parts {
		if part != "" {
			hasValue = true
			break
		}
	}
	if !hasValue {
		return ""
	}
	return strings.Join(parts, "|")
}

func (g GeoLocation) distanceKM(other GeoLocation) (float64, bool) {
	if !g.HasCoordinates || !other.HasCoordinates {
		return 0, false
	}

	const earthRadiusKM = 6371.0
	lat1 := g.Latitude * math.Pi / 180
	lat2 := other.Latitude * math.Pi / 180
	dLat := (other.Latitude - g.Latitude) * math.Pi / 180
	dLon := (other.Longitude - g.Longitude) * math.Pi / 180

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1)*math.Cos(lat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadiusKM * c, true
}

type staticGeoIPFile struct {
	Entries []staticGeoIPEntry `json:"entries"`
}

type staticGeoIPEntry struct {
	CIDR        string   `json:"cidr"`
	CountryCode string   `json:"country_code,omitempty"`
	Country     string   `json:"country,omitempty"`
	Region      string   `json:"region,omitempty"`
	City        string   `json:"city,omitempty"`
	Latitude    *float64 `json:"latitude,omitempty"`
	Longitude   *float64 `json:"longitude,omitempty"`
}

type geoIPRecord struct {
	prefix   netip.Prefix
	location GeoLocation
}

// StaticGeoResolver implements longest-prefix GeoIP matching from a local JSON file.
type StaticGeoResolver struct {
	records []geoIPRecord
}

// LoadStaticGeoResolver loads a simple CIDR→location mapping database from JSON.
func LoadStaticGeoResolver(path string) (*StaticGeoResolver, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read geoip data file: %w", err)
	}

	entries, err := parseStaticGeoIPEntries(data)
	if err != nil {
		return nil, err
	}

	records := make([]geoIPRecord, 0, len(entries))
	for i, entry := range entries {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(entry.CIDR))
		if err != nil {
			return nil, fmt.Errorf("parse geoip entry %d CIDR %q: %w", i, entry.CIDR, err)
		}
		if !prefix.IsValid() {
			return nil, fmt.Errorf("parse geoip entry %d CIDR %q: invalid prefix", i, entry.CIDR)
		}
		location := GeoLocation{
			CountryCode: strings.TrimSpace(entry.CountryCode),
			Country:     strings.TrimSpace(entry.Country),
			Region:      strings.TrimSpace(entry.Region),
			City:        strings.TrimSpace(entry.City),
		}
		if entry.Latitude != nil && entry.Longitude != nil {
			location.Latitude = *entry.Latitude
			location.Longitude = *entry.Longitude
			location.HasCoordinates = true
		}
		records = append(records, geoIPRecord{
			prefix:   prefix.Masked(),
			location: location,
		})
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].prefix.Bits() > records[j].prefix.Bits()
	})

	return &StaticGeoResolver{records: records}, nil
}

func parseStaticGeoIPEntries(data []byte) ([]staticGeoIPEntry, error) {
	var entries []staticGeoIPEntry
	if err := json.Unmarshal(data, &entries); err == nil {
		return entries, nil
	}

	var wrapper staticGeoIPFile
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse geoip data file: %w", err)
	}
	return wrapper.Entries, nil
}

// Lookup resolves the first longest-prefix-matching location for ip.
func (r *StaticGeoResolver) Lookup(ip string) (GeoLocation, bool) {
	if r == nil {
		return GeoLocation{}, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return GeoLocation{}, false
	}
	for _, record := range r.records {
		if record.prefix.Contains(addr) {
			return record.location, true
		}
	}
	return GeoLocation{}, false
}
