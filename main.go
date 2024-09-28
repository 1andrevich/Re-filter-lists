package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/v2fly/geoip/lib"
	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

var (
	// GeoIP flags
	list       = flag.Bool("l", false, "List all available input and output formats")
	configFile = flag.String("c", "config.json", "Path to the config file")

	// Geosite flags
	dataPath    = flag.String("datapath", "./data", "Path to your custom 'data' directory")
	outputName  = flag.String("outputname", "dlc.dat", "Name of the generated dat file")
	outputDir   = flag.String("outputdir", "./", "Directory to place all generated files")
	exportLists = flag.String("exportlists", "", "Lists to be flattened and exported in plaintext format, separated by ',' comma")

	mode = flag.String("m", "geoip", "Specify the mode to run: 'geoip' or 'geosite'")
)

func main() {
	flag.Parse()

	switch *mode {
	case "geoip":
		runGeoIP()
	case "geosite":
		runGeosite()
	default:
		log.Fatal("Unknown mode. Use 'geoip' or 'geosite'.")
	}
}

// GeoIP generation logic
func runGeoIP() {
	if *list {
		lib.ListInputConverter()
		lib.ListOutputConverter()
		return
	}

	instance, err := lib.NewInstance()
	if err != nil {
		log.Fatal(err)
	}

	if err := instance.Init(*configFile); err != nil {
		log.Fatal(err)
	}

	if err := instance.Run(); err != nil {
		log.Fatal(err)
	}
}

// Geosite generation logic
func runGeosite() {
	ref := make(map[string][]string)

	// Load and process all ref files
	err := filepath.Walk(*dataPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			ref[info.Name()] = append(ref[info.Name()], path)
		}
		return nil
	})
	if err != nil {
		fmt.Println("Failed: ", err)
		os.Exit(1)
	}

	// Create output directory if not exist
	if _, err := os.Stat(*outputDir); os.IsNotExist(err) {
		if mkErr := os.MkdirAll(*outputDir, 0755); mkErr != nil {
			fmt.Println("Failed: ", mkErr)
			os.Exit(1)
		}
	}

	protoList := new(router.GeoSiteList)
	var existList []string
	for refName, list := range ref {
		pl, err := ParseList(list, ref)
		if err != nil {
			fmt.Println("Failed: ", err)
			os.Exit(1)
		}
		site, err := pl.toProto()
		if err != nil {
			fmt.Println("Failed: ", err)
			os.Exit(1)
		}
		protoList.Entry = append(protoList.Entry, site)

		// Flatten and export plaintext list
		if *exportLists != "" {
			if existList != nil {
				exportPlainTextList(existList, refName, pl)
			} else {
				exportedListSlice := strings.Split(*exportLists, ",")
				for _, exportedListName := range exportedListSlice {
					fileName := filepath.Join(*dataPath, exportedListName)
					_, err := os.Stat(fileName)
					if err == nil || os.IsExist(err) {
						existList = append(existList, exportedListName)
					} else {
						fmt.Printf("'%s' list does not exist in '%s' directory.\n", exportedListName, *dataPath)
					}
				}
				if existList != nil {
					exportPlainTextList(existList, refName, pl)
				}
			}
		}
	}

	// Sort protoList so the marshaled list is reproducible
	sort.SliceStable(protoList.Entry, func(i, j int) bool {
		return protoList.Entry[i].CountryCode < protoList.Entry[j].CountryCode
	})

	protoBytes, err := proto.Marshal(protoList)
	if err != nil {
		fmt.Println("Failed:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*outputDir, *outputName), protoBytes, 0644); err != nil {
		fmt.Println("Failed: ", err)
		os.Exit(1)
	} else {
		fmt.Println(*outputName, "has been generated successfully.")
	}
}

// Additional utility functions for Geosite
// You may include ParseList, toProto, exportPlainTextList here if they are not yet defined in other packages.
