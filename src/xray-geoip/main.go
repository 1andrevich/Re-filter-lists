package main

import (
	"flag"
	"fmt"
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
		fmt.Println()
		lib.ListOutputConverter()
		return
	}

	instance, err := lib.NewInstance()
	if err != nil {
		log.Fatal(err)
	}

	if err := instance.InitConfig(*configFile); err != nil {
		log.Fatal(err)
	}

	if err := instance.Run(); err != nil {
		log.Fatal(err)
	}
}
