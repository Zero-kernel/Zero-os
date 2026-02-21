.PHONY: all build build-shell run run-shell run-shell-gui run-blk run-blk-serial run-smp run-smp-debug clean lint-release lint-smap lint-fetch-add lint

OVMF_PATH = $(shell \
	if [ -f /usr/share/qemu/OVMF.fd ]; then \
		echo /usr/share/qemu/OVMF.fd; \
	elif [ -f /usr/share/ovmf/OVMF.fd ]; then \
		echo /usr/share/ovmf/OVMF.fd; \
	elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then \
		echo /usr/share/OVMF/OVMF_CODE.fd; \
	else \
		find /usr/share/OVMF/ -type f -name "OVMF_CODE*.fd" 2>/dev/null | head -n 1; \
	fi)
QEMU = qemu-system-x86_64
ESP_DIR = $(shell pwd)/esp/EFI/BOOT
KERNEL_LD = $(shell pwd)/kernel/kernel.ld

all: build

build:
	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== 构建完成 ==="

# Build with interactive shell instead of hello test
build-shell:
	@echo "=== 构建 Shell 用户程序 ==="
	cd userspace && \
	cargo build --release --bin shell --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
	cp userspace/target/x86_64-unknown-none/release/shell kernel/src/shell.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) with Shell ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features shell

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Shell模式）==="

# Build with syscall test program
build-syscall-test:
	@echo "=== 构建 Syscall Test 用户程序 ==="
	cd userspace && \
	cargo build --release --bin syscall_test --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
	cp userspace/target/x86_64-unknown-none/release/syscall_test kernel/src/syscall_test.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) with Syscall Test ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features syscall_test

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Syscall Test模式）==="

# Run syscall test (serial output)
run-syscall-test: build-syscall-test
	@echo "=== 启动内核（Syscall Test模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Build with musl test program
build-musl-test:
	@echo "=== 编译 musl 测试程序 ==="
	cd userspace && musl-gcc -static -o hello_musl.elf hello_musl.c
	cp userspace/hello_musl.elf kernel/src/musl_test.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) with Musl Test ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features musl_test

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== musl ELF 信息 ==="
	@readelf -h kernel/src/musl_test.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Musl Test模式）==="

# Run musl test (serial output)
run-musl-test: build-musl-test
	@echo "=== 启动内核（Musl Test模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Build with clone test program
build-clone-test:
	@echo "=== 编译 clone 测试程序 ==="
	cd userspace && musl-gcc -static -o clone_test.elf clone_test.c
	cp userspace/clone_test.elf kernel/src/clone_test.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) with Clone Test ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features clone_test

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== clone ELF 信息 ==="
	@readelf -h kernel/src/clone_test.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Clone Test模式）==="

# Run clone test (serial output)
run-clone-test: build-clone-test
	@echo "=== 启动内核（Clone Test模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# 通用QEMU参数
# -vga std: 强制使用标准VGA模式，确保0xB8000文本缓冲区可用
# 使用默认的i440FX机器类型，其PCI内存布局将BAR放在4GB以下
# (q35会将某些BAR放在高于4GB的地址，超出bootloader的identity mapping范围)
# R39-8 FIX: Add CPU model with SMEP/SMAP/UMIP/RDRAND support
QEMU_COMMON = -bios $(OVMF_PATH) \
	-drive format=raw,file=fat:rw:esp \
	-m 256M \
	-vga std \
	-no-reboot -no-shutdown \
	-cpu qemu64,+smep,+smap,+umip,+rdrand

# virtio-blk 块设备配置 (Phase C: Storage Foundation)
# 默认使用PCI transport（x86 QEMU更可靠），可切换为MMIO
# 使用环境变量 VIRTIO_BLK_TRANSPORT=mmio 切换到MMIO transport
VIRTIO_BLK_TRANSPORT ?= pci
VIRTIO_MMIO_ADDR = 0x10001000

# PCI transport: 标准x86 QEMU配置
QEMU_BLK_PCI = -drive if=none,file=disk-ext2.img,format=raw,id=vdisk0,cache=writeback,discard=unmap \
	-device virtio-blk-pci,drive=vdisk0

# MMIO transport: 用于非PCI平台或特殊配置
QEMU_BLK_MMIO = -drive if=none,file=disk-ext2.img,format=raw,id=vdisk0,cache=writeback,discard=unmap \
	-device virtio-blk-device,drive=vdisk0

ifeq ($(VIRTIO_BLK_TRANSPORT),mmio)
QEMU_BLK = $(QEMU_BLK_MMIO)
else
QEMU_BLK = $(QEMU_BLK_PCI)
endif

# virtio-net 网络设备配置 (Phase D: Network Foundation)
# 使用user-mode网络和virtio-net-pci设备
# romfile= 禁用UEFI网络驱动，让内核处理设备初始化
QEMU_NET = -netdev user,id=net0 \
	-device virtio-net-pci,netdev=net0,romfile=

# 创建64MB ext2虚拟磁盘镜像
# 使用dd确保跨平台兼容性，debugfs可选创建测试文件
disk-ext2.img:
	@echo "=== 创建 64MB ext2 虚拟磁盘镜像 ==="
	dd if=/dev/zero of=$@ bs=1M count=64 2>/dev/null
	mkfs.ext2 -F -L zeroos $@
	@echo "=== 写入测试文件 ==="
	@if command -v debugfs >/dev/null 2>&1; then \
		tmpfile=$$(mktemp); \
		echo "Zero-OS virtio-blk test file" > $$tmpfile; \
		debugfs -w -R "mkdir /test" $@ 2>/dev/null || true; \
		debugfs -w -R "write $$tmpfile /test/hello.txt" $@ 2>/dev/null || true; \
		rm -f $$tmpfile; \
		echo "测试文件已写入: /test/hello.txt"; \
	else \
		echo "警告: debugfs不可用，跳过测试文件创建"; \
	fi

# 默认运行 - 图形窗口模式（可看到VGA输出）
run: build
	@echo "=== 启动内核（图形窗口模式）==="
	@echo "提示：使用Ctrl+Alt+G释放鼠标，Ctrl+Alt+2切换到QEMU监视器"
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET)

# 串口输出模式 - 通过串口查看内核输出
run-serial: build
	@echo "=== 启动内核（串口输出模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) \
		-nographic

# virtio-blk 图形模式 - 附加ext2磁盘镜像
run-blk: build disk-ext2.img
	@echo "=== 启动内核（virtio-blk 图形模式）==="
	@echo "磁盘: disk-ext2.img (64MB ext2)"
	@echo "提示：使用Ctrl+Alt+G释放鼠标，Ctrl+Alt+2切换到QEMU监视器"
	$(QEMU) $(QEMU_COMMON) $(QEMU_BLK) $(QEMU_NET)

# virtio-blk 串口模式 - 便于查看挂载日志
run-blk-serial: build disk-ext2.img
	@echo "=== 启动内核（virtio-blk 串口模式）==="
	@echo "磁盘: disk-ext2.img (64MB ext2)"
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) $(QEMU_BLK) $(QEMU_NET) \
		-nographic

# Shell模式 - 运行交互式Shell（串口输出）
run-shell: build-shell
	@echo "=== 启动内核（Shell串口模式）==="
	@echo "提示：这是一个交互式Shell，输入 help 查看可用命令"
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Shell图形模式 - 运行交互式Shell（VGA窗口 + PS/2键盘）
run-shell-gui: build-shell
	@echo "=== 启动内核（Shell图形模式）==="
	@echo "提示：这是一个交互式Shell，输入 help 查看可用命令"
	@echo "提示：使用Ctrl+Alt+G释放鼠标，Ctrl+Alt+2切换到QEMU监视器"
	$(QEMU) $(QEMU_COMMON)

# 调试模式 - 显示详细的CPU状态和中断信息
run-debug: build
	@echo "=== 启动内核（调试模式）==="
	@echo "提示：查看详细的CPU状态、中断和内存访问信息"
	$(QEMU) $(QEMU_COMMON) \
		-nographic \
		-serial mon:stdio \
		-d int,cpu_reset \
		-D qemu-debug.log

# 详细调试模式 - 记录更多信息到文件
run-verbose: build
	@echo "=== 启动内核（详细调试模式）==="
	@echo "提示：所有调试信息将记录到qemu-verbose.log"
	$(QEMU) $(QEMU_COMMON) \
		-nographic \
		-d int,cpu,mmu,guest_errors \
		-D qemu-verbose.log

# GDB调试模式 - 等待GDB连接
debug: build
	@echo "=== 启动内核（GDB调试模式）==="
	@echo "在另一个终端运行: gdb esp/kernel.elf"
	@echo "然后在GDB中执行: target remote :1234"
	$(QEMU) $(QEMU_COMMON) \
		-nographic \
		-s -S

# 组合模式 - 图形窗口 + 串口输出
run-both: build
	@echo "=== 启动内核（图形+串口模式）==="
	@echo "提示：VGA输出在图形窗口，串口输出在终端"
	$(QEMU) $(QEMU_COMMON) \
		-serial stdio

# 测试模式 - 自动退出（用于CI/CD）
test: build
	@echo "=== 启动内核（测试模式）==="
	timeout 10 $(QEMU) $(QEMU_COMMON) \
		-nographic || true

# SMP测试模式 - 启用多核支持
# 使用 -smp 指定CPU数量（默认2个）
# ACPI MADT表会自动生成，使内核能够发现多核
SMP_CPUS ?= 2
run-smp: build disk-ext2.img
	@echo "=== 启动内核（SMP模式 - $(SMP_CPUS)核）==="
	@echo "磁盘: disk-ext2.img (64MB ext2)"
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) $(QEMU_BLK) $(QEMU_NET) \
		-smp cpus=$(SMP_CPUS) \
		-nographic

# SMP调试模式 - 详细的APIC/IPI日志
run-smp-debug: build disk-ext2.img
	@echo "=== 启动内核（SMP调试模式 - $(SMP_CPUS)核）==="
	@echo "磁盘: disk-ext2.img (64MB ext2)"
	@echo "提示：中断日志记录到 qemu-smp.log"
	$(QEMU) $(QEMU_COMMON) $(QEMU_BLK) $(QEMU_NET) \
		-smp cpus=$(SMP_CPUS) \
		-nographic \
		-d int,cpu_reset \
		-D qemu-smp.log

# H.2.2 CI gate: Reject ungated println! in kernel code.
# Allowed locations: kernel/drivers/ (macro definition), kernel/klog/ (implementation).
# All other crates must use kprintln!, klog!, or klog_always!.
# Comments and doc strings containing println! are excluded.
lint-release:
	@echo "=== Lint: checking for ungated println! ==="
	@HITS=$$(grep -rn '\bprintln!' kernel/ \
		--include='*.rs' \
		--exclude-dir=drivers \
		--exclude-dir=klog \
		| grep -v '^\s*//' \
		| grep -v '//.*println!' \
		| grep -v '///.*println!' \
		| grep -v '//!.*println!' \
		| grep -v '#\[cfg(feature' \
		| grep -v 'macro_rules!' \
		| grep '^\S*\.rs:[0-9]*:\s*println!' \
	) ; \
	if [ -n "$$HITS" ]; then \
		echo "ERROR: Ungated println! found in kernel code:"; \
		echo "$$HITS"; \
		echo ""; \
		echo "Use kprintln!, klog!(Level, ...), or klog_always! instead."; \
		exit 1; \
	else \
		echo "OK: No ungated println! found outside drivers/klog."; \
	fi

# P1-6: SMAP Window Minimization Policy lint.
# Only copy_from_user_safe / copy_to_user_safe (and their helpers inside
# usercopy.rs) may instantiate UserAccessGuard.  Any ad-hoc UserAccessGuard::new()
# in other files widens the SMAP window and bypasses the chunked-copy design.
lint-smap:
	@echo "=== Lint: checking for ad-hoc UserAccessGuard usage ==="
	@HITS=$$(grep -rn 'UserAccessGuard::new()' kernel/ \
		--include='*.rs' \
		| grep -v 'usercopy\.rs' \
		| grep -v '^\s*//' \
		| grep -v '//.*UserAccessGuard' \
	) ; \
	if [ -n "$$HITS" ]; then \
		echo "ERROR: Ad-hoc UserAccessGuard::new() found outside usercopy.rs:"; \
		echo "$$HITS"; \
		echo ""; \
		echo "SMAP policy: only copy_from_user_safe/copy_to_user_safe may lift SMAP."; \
		echo "Use copy_from_user_safe() or copy_to_user_safe() instead."; \
		exit 1; \
	else \
		echo "OK: No ad-hoc UserAccessGuard usage outside usercopy.rs."; \
	fi

# R112-2 / P3-5: Catch bare fetch_add(1 in kernel core / VFS / namespace code.
# ID counters and refcounts MUST use fetch_update + checked_add (R105-5 pattern).
# Legitimate counter-style uses (statistics, events, ticks) annotate with:
#   // lint-fetch-add: allow
# Scoped to high-risk paths; bulk statistics dirs (net/, arch/, sched/, etc.) excluded.
lint-fetch-add:
	@echo "=== Lint: checking for bare fetch_add(1) in core/VFS/namespace paths ==="
	@HITS=$$(grep -rn 'fetch_add(1' \
		kernel/kernel_core/ \
		kernel/vfs/ \
		kernel/mm/page_cache.rs \
		--include='*.rs' \
		| grep -v '// lint-fetch-add: allow' \
		| grep -v '^\s*//' \
		| grep -v '//.*fetch_add' \
	) ; \
	if [ -n "$$HITS" ]; then \
		echo "ERROR: Bare fetch_add(1 found in core/VFS/namespace code:"; \
		echo "$$HITS"; \
		echo ""; \
		echo "ID counters and refcounts MUST use fetch_update + checked_add."; \
		echo "If this is a legitimate counter, add '// lint-fetch-add: allow' on the same line."; \
		exit 1; \
	else \
		echo "OK: No unguarded fetch_add(1 in core/VFS/namespace paths."; \
	fi

# Unified lint target: runs all CI lint checks.
lint: lint-release lint-smap lint-fetch-add

clean:
	cargo clean
	rm -rf kernel-target
	rm -rf bootloader-target
	rm -rf esp
	rm -f qemu-debug.log qemu-verbose.log qemu-smp.log disk-ext2.img

# 用于连接到QEMU监视器
monitor:
	telnet localhost 45454

# 显示帮助信息
help:
	@echo "Zero-OS Makefile 使用说明"
	@echo "================================"
	@echo "构建命令:"
	@echo "  make build        - 编译bootloader和kernel（默认hello程序）"
	@echo "  make build-shell  - 编译bootloader和kernel（交互式shell）"
	@echo ""
	@echo "运行模式:"
	@echo "  make run          - 图形窗口模式（推荐，可看到VGA输出）"
	@echo "  make run-serial   - 串口输出模式（终端显示）"
	@echo "  make run-blk      - virtio-blk磁盘模式（图形）"
	@echo "  make run-blk-serial - virtio-blk磁盘模式（串口）"
	@echo "  make run-shell    - 串口模式运行交互式Shell（终端输入输出）"
	@echo "  make run-shell-gui - 图形模式运行交互式Shell（VGA+键盘）"
	@echo "  make run-debug    - 调试模式（显示中断和CPU状态）"
	@echo "  make run-verbose  - 详细调试（记录到文件）"
	@echo "  make run-both     - 图形+串口组合模式"
	@echo "  make debug        - GDB调试模式（等待GDB连接）"
	@echo "  make test         - 测试模式（10秒后自动退出）"
	@echo ""
	@echo "SMP多核模式:"
	@echo "  make run-smp      - 启用SMP多核模式（默认2核）"
	@echo "  make run-smp SMP_CPUS=4 - 指定4核"
	@echo "  make run-smp-debug - SMP调试模式（记录中断到qemu-smp.log）"
	@echo ""
	@echo "清理命令:"
	@echo "  make clean        - 清理所有构建文件"
	@echo ""
	@echo "提示:"
	@echo "  - 图形模式可以看到完整的VGA输出和集成测试结果"
	@echo "  - 串口模式适合通过脚本自动化测试"
	@echo "  - Shell串口模式：使用终端输入输出，按Ctrl+A X退出"
	@echo "  - Shell图形模式：使用PS/2键盘和VGA显示，Ctrl+Alt+G释放鼠标"
	@echo "  - 调试模式会在qemu-debug.log中记录详细信息"
	@echo "  - SMP模式会启动多个CPU核心，可用SMP_CPUS环境变量指定数量"
	@echo "  - 按Ctrl+C可以随时停止QEMU"
