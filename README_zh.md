# go-mmproxy

这是 [mmproxy](https://github.com/cloudflare/mmproxy) 的 Go 重新实现，旨在改善 mmproxy 的运行时稳定性，同时在连接和数据包吞吐量方面提供潜在的更高性能。

`go-mmproxy` 是一个独立应用程序，它解包 HAProxy 的 [PROXY 协议](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)（也被 NGINX 等其他项目采用），使得到终端服务器的网络连接来自客户端的 IP 地址和端口号，而不是代理服务器的。
由于它们共享基本机制，[Cloudflare 关于 mmproxy 的博客文章](https://blog.cloudflare.com/mmproxy-creative-way-of-preserving-client-ips-in-spectrum/) 很好地解释了 `go-mmproxy` 的工作原理。

## 构建

```shell
go install github.com/Azusa-mikan/go-mmproxy@latest
```

您需要至少 `go 1.21` 来构建 `go-mmproxy` 二进制文件。
如果您的包管理器没有足够新的 golang 版本，请参阅 [Go 入门指南](https://golang.org/doc/install)。

## 要求

`go-mmproxy` 必须：

- 在与代理目标相同的服务器上运行，因为通信通过回环接口进行。目标必须是本地回环地址，不能是其它服务器地址，否则会在目标服务器上触发[反向路径过滤器（Reverse Path Filter，RPF）](https://zh.wikipedia.org/wiki/%E9%80%86%E5%90%91%E8%BD%AC%E5%8F%91)导致数据包会被丢弃；
- 以 root 身份运行或具有 `CAP_NET_ADMIN` 能力以设置 `IP_TRANSPARENT` 套接字选项。

## 运行

### 路由设置

`go-mmproxy` 在启动时会自动设置所需的路由规则。程序配置路由以将所有来自回环的流量重定向回回环：

- IPv4：`ip rule add from 127.0.0.1/8 iif lo table 123` 和 `ip route add local 0.0.0.0/0 dev lo table 123`
- IPv6：`ip -6 rule add from ::1/128 iif lo table 123` 和 `ip -6 route add local ::/0 dev lo table 123`

这些规则在程序退出时会自动清理。

如果自动设置失败或遇到连接问题，您可以手动设置路由规则：

```shell
ip rule add from 127.0.0.1/8 iif lo table 123
ip route add local 0.0.0.0/0 dev lo table 123

ip -6 rule add from ::1/128 iif lo table 123
ip -6 route add local ::/0 dev lo table 123
```

如果给 `go-mmproxy` 指定了 `--mark` 选项，所有路由到回环接口的数据包都会设置该标记。
这可以用于使用 iptables 设置更高级的路由规则，例如当您需要将来自回环的流量路由到机器外部时。

#### 路由 UDP 数据包

由于 UDP 是无连接的，如果套接字绑定到 `0.0.0.0`，内核堆栈将搜索接口以回复伪造的源地址 - 而不是仅使用接收原始数据包的接口。
找到的接口很可能 _不是_ 回环接口，这将避开上述指定的规则。
解决这个问题的最简单方法是将终端服务器的监听器绑定到 `127.0.0.1`（或 `::1`）。
这通常也建议这样做，以避免接收非代理连接。

### 启动 go-mmproxy

```
./go-mmproxy 的用法：
  -4 string
    	IPv4 流量将转发到的地址（默认 "127.0.0.1:443"）
  -6 string
    	IPv6 流量将转发到的地址（默认 "[::1]:443"）
  -allowed-subnets string
    	包含代理服务器允许子网的文件路径
  -close-after int
    	UDP 套接字将被清理的秒数（默认 60）
  -l string
    	代理监听的地址（默认 "0.0.0.0:8443"）
  -listeners int
    	将为监听地址打开的监听器套接字数量（Linux 3.9+）（默认 1）
  -mark int
    	将在出站数据包上设置的标记
  -p string
    	将被代理的协议：tcp, udp（默认 "tcp"）
  -v int
    	0 - 不记录单个连接
    	1 - 记录单个连接中发生的错误
    	2 - 记录单个连接的所有状态变化
```

示例调用：

```shell
sudo ./go-mmproxy -l 0.0.0.0:25577 -4 127.0.0.1:25578 -6 [::1]:25578 --allowed-subnets ./path-prefixes.txt
```

## 基准测试

### 设置

基准测试在配备 Intel Core i9-8950HK CPU @ 2.90GHz（12 个逻辑核心）的 Dell XPS 9570 上运行。代理发送流量的上游服务由 [bpf-echo](https://github.com/path-network/bpf-echo) 服务器模拟。
流量由 [tcpkali](https://github.com/satori-com/tcpkali) v1.1.1 生成。

在所有情况下都使用以下命令进行负载生成（50 个连接，10 秒运行时间，为每个连接发送 PROXYv1 头，使用 `PING\r\n` 作为 TCP 消息）：

```
tcpkali -c 50 -T 10s -e1 'PROXY TCP4 127.0.0.1 127.0.0.1 \{connection.uid} 25578\r\n' -m 'PING\r\n' 127.0.0.1:1122
```

### 结果

|                         | ⇅ Mbps    | ↓ Mbps    | ↑ Mbps    | ↓ pkt/s   | ↑ pkt/s   |
| ----------------------- | --------- | --------- | --------- | --------- | --------- |
| cloudflare/mmproxy      | 1524.454  | 756.385   | 768.069   | 70365.9   | 65921.9   |
| go-mmproxy GOMAXPROCS=1 | 7418.312  | 2858.794  | 4559.518  | 262062.7  | 391334.6  |
| go-mmproxy              | 45483.233 | 16142.348 | 29340.885 | 1477889.6 | 2518271.5 |
| no proxy                | 52640.116 | 22561.129 | 30078.987 | 2065805.4 | 2581621.3 |

![结果柱状图](benchmark.png)
