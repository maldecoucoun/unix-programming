set KERNELVERSION=6.6.17
set KERNELAPPEND="console=ttyS0"

"c:\program files\qemu\qemu-system-x86_64.exe" -smp 2 -kernel ./dist/vmlinuz-%KERNELVERSION% -initrd ./dist/rootfs.cpio.bz2 -append %KERNELAPPEND% -serial mon:stdio -monitor none -nographic -no-reboot -cpu qemu64 -nic none -m 96M
