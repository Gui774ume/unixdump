/*
Copyright © 2021 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package run

import (
	"github.com/spf13/cobra"
)

// UnixDump represents the base command of unixdump
var UnixDump = &cobra.Command{
	Use:  "unixdump",
	RunE: unixdumpCmd,
}

var options CLIOptions

func init() {
	UnixDump.Flags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		"log level, options: panic, fatal, error, warn, info, debug or trace")
	UnixDump.Flags().StringArrayVarP(
		&options.UnixDumpOptions.CommFilters,
		"comm",
		"c",
		[]string{},
		"list of filtered process comms, leave empty to capture everything")
	UnixDump.Flags().IntVarP(
		&options.UnixDumpOptions.PidFilter,
		"pid",
		"p",
		0,
		"pid filter, leave empty to capture everything")
	UnixDump.Flags().BoolVar(
		&options.UnixDumpOptions.PCAPOutput,
		"pcap",
		false,
		"when set, UnixDump will export the captured data in a pcap file")
	UnixDump.Flags().StringArrayVar(
		&options.UnixDumpOptions.SocketFilters,
		"socket",
		[]string{},
		"list of unix sockets you want to listen on, leave empty to capture everything")
}
