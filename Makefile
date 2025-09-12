.PHONY: all build run clean

# 使用找到的OVMF路径
OVMF_PATH = /usr/share/OVMF/OVMF_CODE.fd
QEMU = qemu-system-x86_64
ESP_DIR = esp/EFI/BOOT
KERNEL_LD = $(shell pwd)/kernel/kernel.ld

all: build

build:
	# 构建引导器（使用UEFI目标）
	cargo build --release --package bootloader --target x86_64-unknown-uefi
	
	# 构建内核（使用裸机目标，带正确的链接参数和绝对路径）
	cd kernel && \
	RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
	
	# 创建ESP目录
	mkdir -p $(ESP_DIR)
	
	# 复制UEFI引导器
	cp target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI
	
	# 复制内核文件到ESP根目录（引导器会从这里加载）
	cp target/x86_64-unknown-none/release/kernel esp/kernel.elf
	
	# 验证内核格式
	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "构建完成！"

run: build
	$(QEMU) \
		-bios $(OVMF_PATH) \
		-drive format=raw,file=fat:rw:esp \
		-m 256M \
		-nographic \
		-serial mon:stdio

debug: build
	$(QEMU) \
		-bios $(OVMF_PATH) \
		-drive format=raw,file=fat:rw:esp \
		-m 256M \
		-nographic \
		-s -S

clean:
	cargo clean
	rm -rf esp

# 用于连接到QEMU监视器
monitor:
	telnet localhost 45454
