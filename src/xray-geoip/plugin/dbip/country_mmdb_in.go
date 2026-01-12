package dbip

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
	typeDBIPLiteCountryMMDBIn = "dbipCountryMMDB"
	descDBIPLiteCountryMMDBIn = "Convert DB-IP lite country mmdb database to other formats"
)

var (
	defaultDBIPLiteCountryMMDBFile = filepath.Join("./", "db-ip", "dbip-country-lite.mmdb")
)

func init() {
	lib.RegisterInputConfigCreator(typeDBIPLiteCountryMMDBIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return newDBIPLiteCountryMMDBIn(action, data)
	})
	lib.RegisterInputConverter(typeDBIPLiteCountryMMDBIn, &dbipLiteCountryMMDBIn{
		Description: descDBIPLiteCountryMMDBIn,
	})
}

func newDBIPLiteCountryMMDBIn(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
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
		tmp.URI = defaultDBIPLiteCountryMMDBFile
	}

	// Filter want list
	wantList := make(map[string]bool)
	for _, want := range tmp.Want {
		if want = strings.ToUpper(strings.TrimSpace(want)); want != "" {
			wantList[want] = true
		}
	}

	return &dbipLiteCountryMMDBIn{
		Type:        typeDBIPLiteCountryMMDBIn,
		Action:      action,
		Description: descDBIPLiteCountryMMDBIn,
		URI:         tmp.URI,
		Want:        wantList,
		OnlyIPType:  tmp.OnlyIPType,
	}, nil
}

type dbipLiteCountryMMDBIn struct {
	Type        string
	Action      lib.Action
	Description string
	URI         string
	Want        map[string]bool
	OnlyIPType  lib.IPType
}

func (d *dbipLiteCountryMMDBIn) GetType() string {
	return d.Type
}

func (d *dbipLiteCountryMMDBIn) GetAction() lib.Action {
	return d.Action
}

func (d *dbipLiteCountryMMDBIn) GetDescription() string {
	return d.Description
}

func (d *dbipLiteCountryMMDBIn) Input(container lib.Container) (lib.Container, error) {
	var content []byte
	var err error
	switch {
	case strings.HasPrefix(strings.ToLower(d.URI), "http://"), strings.HasPrefix(strings.ToLower(d.URI), "https://"):
		content, err = lib.GetRemoteURLContent(d.URI)
	default:
		content, err = os.ReadFile(d.URI)
	}
	if err != nil {
		return nil, err
	}

	entries := make(map[string]*lib.Entry, 300)
	err = d.generateEntries(content, entries)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("❌ [type %s | action %s] no entry is generated", typeDBIPLiteCountryMMDBIn, d.Action)
	}

	var ignoreIPType lib.IgnoreIPOption
	switch d.OnlyIPType {
	case lib.IPv4:
		ignoreIPType = lib.IgnoreIPv6
	case lib.IPv6:
		ignoreIPType = lib.IgnoreIPv4
	}

	for _, entry := range entries {
		switch d.Action {
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

func (d *dbipLiteCountryMMDBIn) generateEntries(content []byte, entries map[string]*lib.Entry) error {
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

		if len(d.Want) > 0 && !d.Want[name] {
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
