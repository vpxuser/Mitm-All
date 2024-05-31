# socks2https
A tool that transmits HTTP and HTTPS packets through a SOCKS5 tunnel

一个将http和https数据包通过socks5隧道传输的工具

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

## 其他

如有疑问，请在Issues提出
