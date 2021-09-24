all: build

build-ebpf:
	mkdir -p ebpf/bin
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-g -c -O2 -emit-llvm \
		ebpf/main.c \
		-o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -prefix "ebpf/bin" -o "pkg/assets/probe.go" "ebpf/bin/probe.o"

build:
	mkdir -p bin/
	go build -o bin/ ./cmd/...

run:
	sudo ./bin/unixdump --log-level debug

install:
	sudo cp ./bin/unixdump /usr/bin/
