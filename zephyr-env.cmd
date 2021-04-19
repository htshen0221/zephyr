@echo off
set ZEPHYR_BASE=%~dp0
set ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb
set GNUARMEMB_TOOLCHAIN_PATH=D:\gcc-arm-none-eabi-10-2020-q4-major
if exist "%userprofile%\zephyrrc.cmd" (
	call "%userprofile%\zephyrrc.cmd"
)
