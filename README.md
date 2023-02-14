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
ppl, err := proxyprotocol.NewListener(l, "*", 5, false)

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

The default value for NLB target group attribute `proxy_protocol_v2.client_to_server.header_placement` is `on_first_ack_with_payload`. User need to contact AWS support to change it to `on_first_ack`.

## Lazy Mode

`go-proxyprotocol` support lazy mode for ProxyProtocol header parse. Using this mode the header parse step will postpone to first `Conn.Read` function call. This will handle AWS NLB problem. And user must ensure that the client IP address must be get after a `Conn.Read` call.

Using lazy mode is simple:

```go
// Create listener
l, err := net.Listener("tcp", "...")


// Wrap listener as PROXY protocol listener and enable lazy mode.
ppl, err := proxyprotocol.NewLazyListener(l, "*", 5, false)

...
```

## Fallback-able

`go-proxyprotocol` support fallback-able mode for ProxyProtocol header process. When multiple client with different system connect to the server and some using PROXY protocol some not and it's hard to determine the allowed IP range, just set `fallbackable` parameter to `true`, it can handle this.

```go
// Create listener
l, err := net.Listener("tcp", "...")


// Wrap listener as PROXY protocol listener and enable lazy mode and fallback-able
ppl, err := proxyprotocol.NewLazyListener(l, "*", 5, true)

...
```
