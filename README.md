# socks2https
A tool that converts the SOCKS5 protocol to HTTP and HTTPS protocols

一个将socks5协议转化为http和https协议的工具

## 抓不到包的常见原因

1. 没有正确地将CA证书安装到/system/etc/security/cacerts（即没有将中间人CA证书安装到操作系统证书受信任根目录）
2. 应用设置了SSL Pinning（即只信任应用包下的特定证书）
3. 应用设置了NO_PROXY（即应用不走系统代理）或自行设置了应用层级的代理

## 解决抓包困境的办法

### 安装证书到/system/etc/security/cacerts目录

#### 方法一：直接安装（适合UserDebug版本的系统）

- 先使用remount.bat脚本重新挂载硬盘到系统盘
  - 安卓设备ID：DeviceID，通过`adb devices`命令可以获取
  - wait：重启参数，可选，有些设备需要重启才能挂载成功

```shell
.\remount.bat [安卓设备ID] [wait]
```

- 使用push.bat脚本上传CA证书到安卓设备
  - 证书文件路径：CA证书文件所在的物理路径

```shell
.\push.bat [证书文件路径] [安卓设备ID]
```

#### 方法二：使用面具模块载入（适合真机）

#### 方法三：使用frida动态注入（适合没有内存动态防护的应用）

### 取消证书锁定SSL Unpinning

#### 方法一：使用frida动态注入（适合没有内存动态防护的应用）

#### 方法二：使用面具模块载入（适合真机）

### 使用透明代理（iptables）

#### 方法一：使用具有透明代理功能的代理应用

- 如：Proxifier

#### 方法二：使用frida动态注入（适合没有内存动态防护的应用）

#### 方法三：系统命令设置iptables

## 目的

在针对APP渗透测试过程中，会发现某些APP不走系统代理，排查过后发现并不是SSL Pinning的问题，针对这种情况，如何强制抓去不走系统代理的数据包呢？

- 相信使用过Proxifier的朋友都知道，Proxifier能强制使所有协议都走Socks5代理，那么现在需要一个工具，将Proxifier转发的流量转换为HTTP和HTTPS，这样，不走系统代理的数据包也能被我们抓取到了。
- 其实，Socks5中间人攻击目前也有解决方案，比如说：Yakit、Charles等，但是个人使用体验并不好（原因：Yakit的UI太复杂、Charles没有强大的插件生态支持），所以就开发了这个工具，通过这个工具联动Burp Suite，就能让Burp Suite实现Socks5中间人攻击。

## 使用方法

### 编译

- 编译linux可执行文件

```powershell
set GOOS=linux
set GOARCH=amd64
go build -o socks2https main.go
```

- 编译windows可执行文件

```powershell
set GOOS=windows
set GOARCH=amd64
go build -o socks2https.exe main.go
```

- 编译macOS可执行文件

```powershell
set GOOS=darwin
set GOARCH=amd64
go build -o socks2https main.go
```

### 配置

- 在可执行程序目录下创建一个config文件夹
- 在config文件夹下创建一个config.yml文件，config.yml文件配置参考

```
log:
  # 日志级别1-5
  level: 4
  # 日志颜色开关
  colorSwitch: true
host: 0.0.0.0
socks:
  debugSwitch: false
  port: 1080
  # 客户端连接超时设置，单位秒
  client:
    timeout: 15
  # 下游代理连接超时设置，单位秒
  target:
    timeout: 15
  # 下游代理地址，目前不支持多级代理
  proxy:
    - http://127.0.0.1:8080
  # ture：dns解析交给socks2https工具完成，false：dns解析交给下游代理完成
  # 建议默认使用false
  bound: false
```

### 运行

- 打开命令行，并进入可执行程序所在目录
- 运行可执行程序

```powershell
.\socks2https.exe
```

### 代理

- 使用socks5代理客户端配置代理，这里使用proxifier做演示

![proxifier配置](./images/1.png)

- 安装抓包工具证书到移动设备或模拟器（注意：需要root权限），这里使用burpsuite
- 在config.yml文件配置下游代理为burpsuite代理地址（这里使用burpsuite默认地址http://127.0.0.1:8080）
- 抓包

![burp抓包](./images/2.png)

## 其他

如有疑问，请在Issues提出
