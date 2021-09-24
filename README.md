## UnixDump

UnixDump is a small eBPF powered utility that can be used to dump unix socket traffic.

### System requirements

This project was developed on an Ubuntu Hirsute machine (Linux Kernel 5.11).

- golang 1.16+
- Kernel headers are expected to be installed in `lib/modules/$(uname -r)`, update the `Makefile` with their location otherwise.
- clang & llvm 11.0.1+

### Build

1) If you need to rebuild the eBPF programs, use the following command:

```shell script
# ~ make build-ebpf
```

2) To build UnixDump, run:

```shell script
# ~ make build
```

3) To install UnixDump (copy to /usr/bin/unixdump) run:
```shell script
# ~ make install
```

### Getting started

UnixDump needs to run as root. Run `sudo unixdump -h` to get help.

```shell script
# ~ unixdump -h
Usage:
  unixdump [flags]

Flags:
  -c, --comm stringArray     list of filtered process comms, leave empty to capture everything
  -h, --help                 help for unixdump
  -l, --log-level string     log level, options: panic, fatal, error, warn, info, debug or trace (default "info")
      --pcap                 when set, UnixDump will export the captured data in a pcap file
  -p, --pid int              pid filter, leave empty to capture everything
      --socket stringArray   list of unix sockets you want to listen on, leave empty to capture everything
```