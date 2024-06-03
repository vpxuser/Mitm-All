# socks2https
A tool that converts the SOCKS5 protocol to HTTP and HTTPS protocols

一个将socks5协议转化为http和https协议的工具

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
