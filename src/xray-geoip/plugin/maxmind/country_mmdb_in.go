package maxmind

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
	"github.com/v2fly/geoip/lib"
)

const (
	typeGeoLite2CountryMMDBIn = "maxmindMMDB"
	descGeoLite2CountryMMDBIn = "Convert MaxMind GeoLite2 country mmdb database to other formats"
)

var (
	defaultGeoLite2CountryMMDBFile = filepath.Join("./", "geolite2", "GeoLite2-Country.mmdb")
)

func init() {
	lib.RegisterInputConfigCreator(typeGeoLite2CountryMMDBIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return newGeoLite2CountryMMDBIn(action, data)
	})
	lib.RegisterInputConverter(typeGeoLite2CountryMMDBIn, &geoLite2CountryMMDBIn{
		Description: descGeoLite2CountryMMDBIn,
	})
}

func newGeoLite2CountryMMDBIn(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
	var tmp struct {
		URI        string     `json:"uri"`
		Want       []string   `json:"wantedList"`
		OnlyIPType lib.IPType `json:"onlyIPType"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.URI == "" {
		tmp.URI = defaultGeoLite2CountryMMDBFile
	}

	// Filter want list
	wantList := make(map[string]bool)
	for _, want := range tmp.Want {
		if want = strings.ToUpper(strings.TrimSpace(want)); want != "" {
			wantList[want] = true
		}
	}

	return &geoLite2CountryMMDBIn{
		Type:        typeGeoLite2CountryMMDBIn,
		Action:      action,
		Description: descGeoLite2CountryMMDBIn,
		URI:         tmp.URI,
		Want:        wantList,
		OnlyIPType:  tmp.OnlyIPType,
	}, nil
}

type geoLite2CountryMMDBIn struct {
	Type        string
	Action      lib.Action
	Description string
	URI         string
	Want        map[string]bool
	OnlyIPType  lib.IPType
}

func (g *geoLite2CountryMMDBIn) GetType() string {
	return g.Type
}

func (g *geoLite2CountryMMDBIn) GetAction() lib.Action {
	return g.Action
}

func (g *geoLite2CountryMMDBIn) GetDescription() string {
	return g.Description
}

func (g *geoLite2CountryMMDBIn) Input(container lib.Container) (lib.Container, error) {
	var content []byte
	var err error
	switch {
	case strings.HasPrefix(strings.ToLower(g.URI), "http://"), strings.HasPrefix(strings.ToLower(g.URI), "https://"):
		content, err = lib.GetRemoteURLContent(g.URI)
	default:
		content, err = os.ReadFile(g.URI)
	}
	if err != nil {
		return nil, err
	}

	entries := make(map[string]*lib.Entry, 300)
	err = g.generateEntries(content, entries)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("❌ [type %s | action %s] no entry is generated", typeGeoLite2CountryMMDBIn, g.Action)
	}

	var ignoreIPType lib.IgnoreIPOption
	switch g.OnlyIPType {
	case lib.IPv4:
		ignoreIPType = lib.IgnoreIPv6
	case lib.IPv6:
		ignoreIPType = lib.IgnoreIPv4
	}

	for _, entry := range entries {
		switch g.Action {
		case lib.ActionAdd:
			if err := container.Add(entry, ignoreIPType); err != nil {
				return nil, err
			}
		case lib.ActionRemove:
			if err := container.Remove(entry, lib.CaseRemovePrefix, ignoreIPType); err != nil {
				return nil, err
			}
		default:
			return nil, lib.ErrUnknownAction
		}
	}

	return container, nil
}

func (g *geoLite2CountryMMDBIn) generateEntries(content []byte, entries map[string]*lib.Entry) error {
	db, err := maxminddb.FromBytes(content)
	if err != nil {
		return err
	}
	defer db.Close()

	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var record geoip2.Country
		subnet, err := networks.Network(&record)
		if err != nil {
			return err
		}

		name := ""
		switch {
		case strings.TrimSpace(record.Country.IsoCode) != "":
			name = strings.ToUpper(strings.TrimSpace(record.Country.IsoCode))
		case strings.TrimSpace(record.RegisteredCountry.IsoCode) != "":
			name = strings.ToUpper(strings.TrimSpace(record.RegisteredCountry.IsoCode))
		case strings.TrimSpace(record.RepresentedCountry.IsoCode) != "":
			name = strings.ToUpper(strings.TrimSpace(record.RepresentedCountry.IsoCode))
		default:
			continue
		}

		if len(g.Want) > 0 && !g.Want[name] {
			continue
		}

		entry, found := entries[name]
		if !found {
			entry = lib.NewEntry(name)
		}

		if err := entry.AddPrefix(subnet); err != nil {
			return err
		}

		entries[name] = entry
	}

	if networks.Err() != nil {
		return networks.Err()
	}

	return nil
}
