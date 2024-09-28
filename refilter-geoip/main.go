// GeoIP generator
//
// Before running this file, the GeoIP database must be downloaded and present.
// To download GeoIP database: https://dev.maxmind.com/geoip/geoip2/geolite2/
// Inside you will find block files for IPv4 and IPv6 and country code mapping.
package main

import (
	"flag"
	"log"

	"github.com/v2fly/geoip/lib"
)

var (
	list       = flag.Bool("l", false, "List all available input and output formats")
	configFile = flag.String("c", "config.json", "Path to the config file")
)

func main() {
	flag.Parse()

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
