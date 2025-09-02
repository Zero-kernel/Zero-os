.PHONY: all build run clean

# 使用找到的OVMF路径
OVMF_PATH = /usr/share/OVMF/OVMF_CODE.fd
QEMU = qemu-system-x86_64
ESP_DIR = esp/EFI/BOOT

all: build

build:
	# 构建引导器（使用UEFI目标）
	cargo build --release --package bootloader --target x86_64-unknown-uefi
	
	# 构建内核（使用裸机目标）
	cargo build --release --package kernel --target x86_64-unknown-none
	
	# 创建ESP目录
	mkdir -p $(ESP_DIR)
	
	# 复制UEFI引导器
	cp target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI
	
	# 复制内核文件到ESP
	cp target/x86_64-unknown-none/release/kernel esp/kernel.elf
	
	@echo "构建完成！"

run: build
	$(QEMU) \
		-bios $(OVMF_PATH) \
		-drive format=raw,file=fat:rw:esp \
		-serial stdio \
		-m 256M \
		-nographic

debug: build
	$(QEMU) \
		-bios $(OVMF_PATH) \
		-drive format=raw,file=fat:rw:esp \
		-serial stdio \
		-m 256M \
		-nographic \
		-s -S

clean:
	cargo clean
	rm -rf esp
