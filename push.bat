@echo off
setlocal enabledelayedexpansion

chcp 65001 > nul

:: 检查是否安装OpenSSL
openssl version > nul 2>&1
if errorlevel 1 (
    echo OpenSSL 未安装或未配置在系统路径中。
    echo 请安装OpenSSL并确保其已添加到系统环境变量PATH中。
    exit /b 1
)

:: 检查是否提供了证书文件路径参数
if "%~1"=="" (
    echo 使用说明:
    echo.
    echo 该脚本用于获取证书文件的旧格式主题哈希，并将其拷贝并重命名，然后通过 ADB 上传到设备的 system/etc/security/cacerts 文件夹。
    echo.
    echo 用法:
    echo   push.bat [证书文件路径] [设备ID]
    echo.
    echo 参数说明:
    echo   证书文件路径: 必选参数，指定要上传的证书文件路径。
    echo   设备ID: 可选参数，指定要执行操作的设备ID。如果不提供，则操作默认设备。
    echo.
    echo 示例:
    echo   push.bat certificate.pem emulator-5554
    echo.
    echo 注意: 本脚本需要安装ADB工具并配置环境变量。
    echo.
    exit /b 1
)

set CERT_FILE=%1
set DEVICE_ID=%2
set SUCCESS=1
set HASH=""
set ADB_COMMAND=adb

if not "%DEVICE_ID%"=="" (
    set ADB_COMMAND=adb -s %DEVICE_ID%
)

:: 尝试读取证书并获取哈希
call :GET_CERT_HASH "%CERT_FILE%" "PEM"
if errorlevel 1 call :GET_CERT_HASH "%CERT_FILE%" "DER"

if "%HASH%"=="" (
    echo 无法确定证书格式或获取哈希失败。
    exit /b 1
)

:: 拷贝并重命名证书文件
copy "%CERT_FILE%" "%HASH%.0" > nul
if errorlevel 1 (
    echo 拷贝文件失败。
    exit /b 1
) else (
    echo 拷贝并重命名文件成功：%HASH%.0
)

:: 上传证书文件到设备
%ADB_COMMAND% push "%HASH%.0" /system/etc/security/cacerts/
if errorlevel 1 (
    echo 证书文件上传失败。
    exit /b 1
) else (
    echo 证书文件上传成功：/system/etc/security/cacerts/%HASH%.0
    :: 设置证书文件权限
    %ADB_COMMAND% shell chmod 644 /system/etc/security/cacerts/%HASH%.0
    if errorlevel 1 (
        echo 设置证书文件权限失败。
        exit /b 1
    ) else (
        echo 设置证书文件权限成功。
    )
)

echo 成功完成所有操作。

:: 清理临时文件
if exist "%HASH%.0" del "%HASH%.0"

exit /b 0

:GET_CERT_HASH
setlocal
set CERT_FILE=%1
set FORMAT=%2
openssl x509 -in "%CERT_FILE%" -inform %FORMAT% -text -noout > nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%a in ('openssl x509 -inform %FORMAT% -subject_hash_old -in "%CERT_FILE%"') do (
        endlocal
        set "HASH=%%a"
        echo %FORMAT% 格式证书的哈希: %%a
        exit /b 0
    )
)
endlocal
exit /b 1
