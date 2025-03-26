// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/go-openapi/loads"

	healthServer "github.com/cilium/cilium/api/v1/health/server"
	operatorServer "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/pkg/api"
)

var (
	MainCell = cell.Module(
		"main",
		"Main module for generating API configuration tables",

		cell.Invoke(printAPIFlagTables),
	)
	Hive = hive.New(
		server.SpecCell,
		healthServer.SpecCell,
		operatorServer.SpecCell,
		MainCell,
	)
)

func wrap(in string, width int) []string {
	result := make([]string, 0, len(in)/width)
	if len(in) == 0 {
		return []string{"-"}
	}

	fields := strings.Fields(in)
	current := fields[0]
	for _, f := range fields[1:] {
		if len(current)+len(f)+1 > width {
			result = append(result, current)
			current = f
			continue
		}
		current = current + " " + f
	}
	if len(current) != 0 {
		result = append(result, current)
	}
	return result
}

func writeTable(wr io.Writer, spec *loads.Document) {
	flagWidth := 20
	colWidth := 80
	tabWriter := tabwriter.NewWriter(wr, flagWidth, 0, 1, ' ', tabwriter.TabIndent)

	fmt.Fprintln(tabWriter, "=====================\t====================")
	fmt.Fprintln(tabWriter, "Flag Name \tDescription")
	fmt.Fprintln(tabWriter, "=====================\t====================")

	pathSet := api.NewPathSet(spec)
	for _, k := range slices.Sorted(maps.Keys(pathSet)) {
		desc := strings.TrimSuffix(pathSet[k].Description, "\n")
		wrapped := wrap(desc, colWidth-flagWidth)
		fmt.Fprintln(tabWriter, k+"\t"+wrapped[0])
		for i := 1; i < len(wrapped); i++ {
			fmt.Fprintln(tabWriter, " \t"+wrapped[i])
		}
	}
	fmt.Fprintln(tabWriter, "=====================\t====================")
	tabWriter.Flush()
}

func writeFlagPreamble(wr io.Writer, binary, flag string) {
	fmt.Fprintf(wr, "The following API flags are compatible with the ``%s`` flag\n``%s``.\n\n",
		binary, flag)
}

func writeTitle(wr io.Writer, title string) {
	fmt.Fprintf(wr, "\n%s\n", title)
	fmt.Fprint(wr, strings.Map(func(r rune) rune {
		return '='
	}, title)+"\n\n")
}

func printAPIFlagTables(
	spec *server.Spec,
	healthSpec *healthServer.Spec,
	opSpec *operatorServer.Spec,
	shutdown hive.Shutdowner,
) {
	wr := os.Stdout

	fmt.Fprintf(wr, ".. <!-- This file was autogenerated via api-flaggen, do not edit manually-->\n")
	writeTitle(wr, "Cilium Agent API")
	writeFlagPreamble(wr, "cilium-agent", "enable-cilium-api-server-access")
	writeTable(wr, spec.Document)
	writeTitle(wr, "Cilium Agent Clusterwide Health API")
	writeFlagPreamble(wr, "cilium-agent", "enable-cilium-health-api-server-access")
	writeTable(wr, healthSpec.Document)
	writeTitle(wr, "Cilium Operator API")
	writeFlagPreamble(wr, "cilium-operator", "enable-cilium-operator-server-access")
	writeTable(wr, opSpec.Document)
	shutdown.Shutdown()
}

func main() {
	Hive.Run(slog.New(slog.DiscardHandler))
}
