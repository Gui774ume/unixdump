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
	"context"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"

	"github.com/google/gopacket/layers"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/unixdump/pkg/ringbuf"
)

// UnixDump is the main UnixDump structure
type UnixDump struct {
	options    Options
	dumpFile   *os.File
	pcapWriter *pcapgo.NgWriter

	ctx        context.Context
	cancelFunc context.CancelFunc
	wg         *sync.WaitGroup
	cpuCount   int

	manager         *manager.Manager
	managerOptions  manager.Options
	startTime       time.Time
	commFilterMap   *ebpf.Map
	socketFilterMap *ebpf.Map

	reader         *ringbuf.Reader
	packetsCounter uint64
}

// NewUnixDump creates a new UnixDump instance
func NewUnixDump(options Options) (*UnixDump, error) {
	var err error

	e := &UnixDump{
		wg:      &sync.WaitGroup{},
		options: options,
	}

	if options.PCAPOutput {
		e.dumpFile, err = ioutil.TempFile("/tmp", "unixdump-*.pcap")
		if err != nil {
			return nil, err
		}
		if err = os.Chmod(e.dumpFile.Name(), 0777); err != nil {
			return nil, err
		}
		e.pcapWriter, err = pcapgo.NewNgWriter(e.dumpFile, layers.LinkTypeNull)
		if err != nil {
			logrus.Errorf("couldn't create pcap writer: %s", err)
		}
	}

	e.cpuCount, err = NumCPU()
	if err != nil {
		return nil, err
	}

	e.ctx, e.cancelFunc = context.WithCancel(context.Background())
	return e, nil
}

// Start hooks on the requested symbols and begins tracing
func (e *UnixDump) Start() error {
	if err := e.startManager(); err != nil {
		return err
	}

	if err := e.pushFilters(); err != nil {
		return errors.Wrap(err, "couldn't push filters to the kernel")
	}

	logrus.Infoln("tracing started (Ctrl + C to stop)\n")
	if e.dumpFile != nil {
		logrus.Infof("pcap output: %s", e.dumpFile.Name())
	}
	return nil
}

// Stop shuts down UnixDump
func (e *UnixDump) Stop() error {
	if e.manager == nil {
		// nothing to stop, return
		return nil
	}
	return e.stop()
}

func (e *UnixDump) stop() error {
	e.cancelFunc()

	// close ringbuf reader
	e.reader.Close()
	e.wg.Wait()

	// Close the manager
	if err := e.manager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}

	// write pcap header
	if e.pcapWriter != nil {
		if err := e.pcapWriter.Flush(); err != nil {
			logrus.Errorf("couldn't flush pcap writer: %s", err)
		}
	}
	if e.dumpFile != nil {
		_ = e.dumpFile.Close()
	}

	e.showStats()
	return nil
}

func (e *UnixDump) showStats() {
	logrus.Infof("%d packets captured", e.packetsCounter)
}

func (e *UnixDump) pushFilters() error {
	var err error
	filter := uint32(1)

	if len(e.options.CommFilters) > 0 {
		for _, comm := range e.options.CommFilters {
			commB := make([]byte, 16)
			copy(commB[:], comm)
			err = e.commFilterMap.Put(commB, filter)
			if err != nil {
				return errors.Wrapf(err, "couldn't push comm filter for \"%s\"", comm)
			}
		}
	}

	if len(e.options.SocketFilters) > 0 {
		for _, socketPath := range e.options.SocketFilters {
			socketB := make([]byte, 255)
			copy(socketB, socketPath)
			err = e.socketFilterMap.Put(socketB, filter)
			if err != nil {
				return errors.Wrapf(err, "couldn't push socket filter for \"%s\"", socketPath)
			}
		}
	}

	return nil
}

func (e *UnixDump) handleEvent(data []byte) {
	e.packetsCounter++

	var evt UnixEvent
	if err := evt.UnmarshallBinary(data); err != nil {
		logrus.Debugf("couldn't parse UnixEvent: %s", err)
		return
	}

	// write pcap file
	if e.pcapWriter != nil {
		capInfo := gopacket.CaptureInfo{
			Length:        int(evt.PacketLen),
			CaptureLength: int(evt.PacketLen),
			Timestamp:     time.Now(),
		}

		if err := e.pcapWriter.WritePacket(capInfo, evt.Data); err != nil {
			logrus.Debugf("couldn't write packet in capture file: %s", err)
		}
	}

	// call event handler
	if e.options.EventHandler != nil {
		e.options.EventHandler(evt)
	}
}
