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
	"errors"
	"fmt"

	"github.com/Gui774ume/unixdump/pkg/utils"
)

// ErrNotEnoughData not enough data
var ErrNotEnoughData = errors.New("not enough data")

// Options contains the parameters of UnixDump
type Options struct {
	CommFilters   []string
	PidFilter     int
	SocketFilters []string
	EventHandler  func(event UnixEvent)
	PCAPOutput    bool
}

func (o Options) check() error {
	return nil
}

// UnixEvent holds the content of a captured unix message
type UnixEvent struct {
	PID       uint32
	PeerPID   uint32
	PacketLen uint32
	SocketLen uint32
	Comm      string
	Socket    string
	Data      []byte
}

func (ue UnixEvent) String() string {
	return fmt.Sprintf(
		"PID:%d PeerPID:%d PacketLen:%d SocketLen:%d Comm:%s Socket:%s Data:\"%v\"",
		ue.PID,
		ue.PeerPID,
		ue.PacketLen,
		ue.SocketLen,
		ue.Comm,
		ue.Socket,
		string(ue.Data),
	)
}

// UnmarshallBinary unmarshall a UnixEvent from its binary representation
func (ue *UnixEvent) UnmarshallBinary(data []byte) error {
	if len(data) < 32 {
		return fmt.Errorf("got %d bytes, expected 32: %w", len(data), ErrNotEnoughData)
	}
	ue.PID = utils.ByteOrder.Uint32(data[0:4])
	ue.PeerPID = utils.ByteOrder.Uint32(data[4:8])
	ue.PacketLen = utils.ByteOrder.Uint32(data[8:12])
	ue.SocketLen = utils.ByteOrder.Uint32(data[12:16])
	ue.Comm = bytes.NewBuffer(bytes.Trim(data[16:32], "\x00")).String()

	if len(data) < 32+int(ue.SocketLen) {
		return fmt.Errorf("got %d bytes, expected %d: %w", len(data), 32+int(ue.SocketLen), ErrNotEnoughData)
	}
	ue.Socket = bytes.NewBuffer(bytes.Trim(data[32:32+ue.SocketLen], "\x00")).String()

	if len(data) < 32+int(ue.SocketLen+ue.PacketLen) {
		return fmt.Errorf("got %d bytes, expected %d: %w", len(data), 32+int(ue.SocketLen+ue.PacketLen), ErrNotEnoughData)
	}
	ue.Data = data[32+ue.SocketLen:]
	return nil
}
