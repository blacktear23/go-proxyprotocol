# go-proxyprotocol

[![GoDoc](https://pkg.go.dev/badge/github.com/blacktear23/go-proxyprotocol?utm_source=godoc)](https://pkg.go.dev/github.com/blacktear23/go-proxyprotocol)

PROXY protocol implementation in Go.

## Usage

import

```go
import (
	proxyprotocol "github.com/blacktear23/go-proxyprotocol"
)
```

basic usage

```go
// Create listener
l, err := net.Listen("tcp", "...")

// Wrap listener as PROXY protocol listener
ppl, err := proxyprotocol.NewListener(l, "*", 5)

for {
    conn, err := ppl.Accept()
    if err != nil {
        // PROXY protocol related errors can be output by log and
        // continue accept next one.
        if proxyprotocol.IsProxyProtocolError(err) {
            log.Errorf("PROXY protocol error: %s", err.Error())
            continue
        }
        panic(err)
    }
    go processConn(conn)
}
```

## Notice For AWS NLB

If using AWS NLB, as default NLB will not send ProxyProtocol v2 header to server until client send data. This will cause read timeout error if your server send data first. For example: SMTP, FTP, SSH, MySQL etc.

And doing some packet dump for NLB traffic we also found NLB will send ProxyProtocol v2 header with `UNSPEC` address family. This will let go-proxyprotocol return TCP connection's origin remote address.

The default value for NLB target group attribute `proxy_protocol_v2.client_to_server.header_placement` is `on_first_ack_with_payload`. User need to contact AWS support to change it to `on_first_ack`.
