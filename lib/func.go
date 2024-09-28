package lib

import (
	"fmt"
	"strings"
)

var (
	inputConverterMap  = make(map[string]InputConverter)
	outputConverterMap = make(map[string]OutputConverter)
)

func ListInputConverter() {
	fmt.Println("All available input formats:")
	for name, ic := range inputConverterMap {
		fmt.Printf("  - %s (%s)\n", name, ic.GetDescription())
	}
}

func RegisterInputConverter(name string, c InputConverter) error {
	name = strings.TrimSpace(name)
	if _, ok := inputConverterMap[name]; ok {
		return ErrDuplicatedConverter
	}
	inputConverterMap[name] = c
	return nil
}

func ListOutputConverter() {
	fmt.Println("All available output formats:")
	for name, oc := range outputConverterMap {
		fmt.Printf("  - %s (%s)\n", name, oc.GetDescription())
	}
}

func RegisterOutputConverter(name string, c OutputConverter) error {
	name = strings.TrimSpace(name)
	if _, ok := outputConverterMap[name]; ok {
		return ErrDuplicatedConverter
	}
	outputConverterMap[name] = c
	return nil
}
