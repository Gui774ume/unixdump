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

package unixdump

import (
	"bytes"
	"math"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/unixdump/pkg/assets"
	"github.com/Gui774ume/unixdump/pkg/ringbuf"
)

func (e *UnixDump) prepareManager() {
	e.manager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  "kprobe/unix_stream_sendmsg",
					EBPFFuncName: "kprobe_unix_stream_sendmsg",
				},
			},
		},
	}
	e.managerOptions = manager.Options{
		// DefaultKProbeMaxActive is the maximum number of active kretprobe at a given time
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// LogSize is the size of the log buffer given to the verifier. Give it a big enough (2 * 1024 * 1024)
				// value so that all our programs fit. If the verifier ever outputs a `no space left on device` error,
				// we'll need to increase this value.
				LogSize: 2097152,
			},
		},

		// Extend RLIMIT_MEMLOCK (8) size
		// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
		// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
		// using bpf(2) with BPF_MAP_CREATE.
		//
		// We are setting the limit to infinity until we have a better handle on the true requirements.
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	if len(e.options.CommFilters) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "comm_filter",
			Value: uint64(1),
		})
	}

	if e.options.PidFilter > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "pid_filter",
			Value: uint64(e.options.PidFilter),
		})
	}

	if len(e.options.SocketFilters) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "socket_filter",
			Value: uint64(1),
		})
	}

	e.managerOptions.MapSpecEditors = map[string]manager.MapSpecEditor{
		"unix_event_gen": {
			MaxEntries: uint32(e.cpuCount),
			EditorFlag: manager.EditMaxEntries,
		},
	}
}

func (e *UnixDump) selectMaps() error {
	var err error
	ring, _, err := e.manager.GetMap("events")
	if err != nil || ring == nil {
		return errors.Errorf("couldn't find \"events\" map")
	}
	e.reader, err = ringbuf.NewReader(ring)
	if err != nil {
		return errors.Errorf("couldn't instantiate a new ring buffer reader: %v", err)
	}
	e.commFilterMap, _, err = e.manager.GetMap("comm_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"comm_filters\" map")
	}
	e.socketFilterMap, _, err = e.manager.GetMap("socket_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"socket_filters\" map")
	}
	return nil
}

func (e *UnixDump) startManager() error {
	// fetch ebpf assets
	buf, err := assets.Asset("/probe.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup a default manager
	e.prepareManager()

	// initialize the manager
	if err := e.manager.InitWithOptions(bytes.NewReader(buf), e.managerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// select kernel space maps
	if err := e.selectMaps(); err != nil {
		return err
	}

	// start the manager
	if err := e.manager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start manager")
	}

	e.startTime = time.Now()

	go func(e *UnixDump) {
		if e == nil {
			return
		}
		e.wg.Add(1)
		defer e.wg.Done()

		var sample ringbuf.Record
		var err error

		for {
			sample, err = e.reader.Read()
			if err != nil {
				select {
				case <-e.ctx.Done():
					return
				default:
				}
				continue
			}
			e.handleEvent(sample.RawSample)
		}
	}(e)
	return nil
}
