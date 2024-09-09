@echo off
setlocal EnableDelayedExpansion
chcp 65001 > nul

if "%~1"=="" (
    echo 使用说明:
    echo.
    echo 该脚本用于执行重新挂载 Android 系统盘操作。
    echo.
    echo 用法:
    echo   remount.bat [设备ID] [等待参数]
    echo.
    echo 参数说明:
    echo   设备ID: 可选参数，指定要执行操作的设备ID。
    echo   等待参数: 可选参数，当值为 "wait" 时，脚本将等待设备重启和启动完成。
    echo.
    echo 示例:
    echo   remount.bat emulator-5554 wait
    echo.
    echo 注意: 本脚本需要安装ADB工具并配置环境变量。
    echo.
)

echo 正在列出所有设备...
adb devices

set DEVICE_ID=%1
set WAIT_PARAM=%2
set SUCCESS=1
set ADB_COMMAND=adb

if not "%DEVICE_ID%"=="" (
    set ADB_COMMAND=adb -s %DEVICE_ID%
)

REM 获取 ROOT 权限
%ADB_COMMAND% root && (
    echo 获取 ROOT 权限成功.
) || (
    echo 获取 ROOT 权限失败.
    set SUCCESS=0
)

REM 禁用 Android 验证机制
%ADB_COMMAND% disable-verity && (
    echo 禁用 Android 验证机制成功.
) || (
    echo 禁用 Android 验证机制失败.
    set SUCCESS=0
)

if "%WAIT_PARAM%"=="wait" (
    REM 设备重启
    %ADB_COMMAND% reboot && (
        echo 设备重启成功.
    ) || (
        echo 设备重启失败.
        set SUCCESS=0
    )

    echo 等待设备重启...
    timeout /t 10 > nul

    echo 等待设备启动完成...
    %ADB_COMMAND% wait-for-device && (
        echo 设备启动完成.
    ) || (
        echo 等待设备失败.
        set SUCCESS=0
    )

    :CHECK_BOOT_COMPLETED
    %ADB_COMMAND% shell getprop sys.boot_completed | findstr /c:"1" > nul
    if errorlevel 1 (
        echo 设备尚未启动完成，等待中...
        timeout /t 5 > nul
        goto CHECK_BOOT_COMPLETED
    ) else (
        echo 设备已经启动完成.
    )

    REM 再次获取 ROOT 权限
    %ADB_COMMAND% root && (
        echo 获取 ROOT 权限成功.
    ) || (
        echo 获取 ROOT 权限失败.
        set SUCCESS=0
    )
)

REM 重新挂载系统盘
%ADB_COMMAND% remount && (
    echo 重新挂载系统盘成功.
) || (
    echo 重新挂载系统盘失败，尝试 mount 重新挂载 /system 分区...
    %ADB_COMMAND% shell mount -o rw,remount /system && (
        echo mount 挂载成功.
    ) || (
        echo mount 挂载失败.
        set SUCCESS=0
    )
)

if "!SUCCESS!"=="1" (
    echo 成功挂载系统盘.
) else (
    echo 挂载系统盘失败.
)
