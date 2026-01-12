package plaintext

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/v2fly/geoip/lib"
)

const (
	typeTextOut = "text"
	descTextOut = "Convert data to plaintext CIDR format"
)

var (
	defaultOutputDir = filepath.Join("./", "output", "text")
)

func init() {
	lib.RegisterOutputConfigCreator(typeTextOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return newTextOut(action, data)
	})
	lib.RegisterOutputConverter(typeTextOut, &textOut{
		Description: descTextOut,
	})
}

func newTextOut(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
	var tmp struct {
		OutputDir  string     `json:"outputDir"`
		OutputExt  string     `json:"outputExtension"`
		Want       []string   `json:"wantedList"`
		Exclude    []string   `json:"excludedList"`
		OnlyIPType lib.IPType `json:"onlyIPType"`

		AddPrefixInLine string `json:"addPrefixInLine"`
		AddSuffixInLine string `json:"addSuffixInLine"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.OutputDir == "" {
		tmp.OutputDir = defaultOutputDir
	}

	if tmp.OutputExt == "" {
		tmp.OutputExt = ".txt"
	}

	return &textOut{
		Type:        typeTextOut,
		Action:      action,
		Description: descTextOut,
		OutputDir:   tmp.OutputDir,
		OutputExt:   tmp.OutputExt,
		Want:        tmp.Want,
		Exclude:     tmp.Exclude,
		OnlyIPType:  tmp.OnlyIPType,

		AddPrefixInLine: tmp.AddPrefixInLine,
		AddSuffixInLine: tmp.AddSuffixInLine,
	}, nil
}

type textOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputDir   string
	OutputExt   string
	Want        []string
	Exclude     []string
	OnlyIPType  lib.IPType

	AddPrefixInLine string
	AddSuffixInLine string
}

func (t *textOut) GetType() string {
	return t.Type
}

func (t *textOut) GetAction() lib.Action {
	return t.Action
}

func (t *textOut) GetDescription() string {
	return t.Description
}

func (t *textOut) Output(container lib.Container) error {
	for _, name := range t.filterAndSortList(container) {
		entry, found := container.GetEntry(name)
		if !found {
			log.Printf("❌ entry %s not found\n", name)
			continue
		}

		cidrList, err := t.marshalText(entry)
		if err != nil {
			return err
		}

		filename := strings.ToLower(entry.GetName()) + t.OutputExt
		if err := t.writeFile(filename, cidrList); err != nil {
			return err
		}
	}

	return nil
}

func (t *textOut) filterAndSortList(container lib.Container) []string {
	excludeMap := make(map[string]bool)
	for _, exclude := range t.Exclude {
		if exclude = strings.ToUpper(strings.TrimSpace(exclude)); exclude != "" {
			excludeMap[exclude] = true
		}
	}

	wantList := make([]string, 0, len(t.Want))
	for _, want := range t.Want {
		if want = strings.ToUpper(strings.TrimSpace(want)); want != "" && !excludeMap[want] {
			wantList = append(wantList, want)
		}
	}

	if len(wantList) > 0 {
		// Sort the list
		slices.Sort(wantList)
		return wantList
	}

	list := make([]string, 0, 300)
	for entry := range container.Loop() {
		name := entry.GetName()
		if excludeMap[name] {
			continue
		}
		list = append(list, name)
	}

	// Sort the list
	slices.Sort(list)

	return list
}

func (t *textOut) marshalText(entry *lib.Entry) ([]string, error) {
	var entryCidr []string
	var err error
	switch t.OnlyIPType {
	case lib.IPv4:
		entryCidr, err = entry.MarshalText(lib.IgnoreIPv6)
		if err != nil {
			return nil, err
		}
	case lib.IPv6:
		entryCidr, err = entry.MarshalText(lib.IgnoreIPv4)
		if err != nil {
			return nil, err
		}
	default:
		entryCidr, err = entry.MarshalText()
		if err != nil {
			return nil, err
		}
	}

	return entryCidr, nil
}

func (t *textOut) writeFile(filename string, cidrList []string) error {
	var buf bytes.Buffer
	for _, cidr := range cidrList {
		if t.AddPrefixInLine != "" {
			buf.WriteString(t.AddPrefixInLine)
		}
		buf.WriteString(cidr)
		if t.AddSuffixInLine != "" {
			buf.WriteString(t.AddSuffixInLine)
		}
		buf.WriteString("\n")
	}
	cidrBytes := buf.Bytes()

	if err := os.MkdirAll(t.OutputDir, 0755); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(t.OutputDir, filename), cidrBytes, 0644); err != nil {
		return err
	}

	log.Printf("✅ [%s] %s --> %s", t.Type, filename, t.OutputDir)

	return nil
}
