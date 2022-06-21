package proxyprotocol

import "testing"

func FuzzHeaderParse(f *testing.F) {
	tests := [][]byte{
		[]byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
		[]byte("PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 2001:0db8:85a3:0000:0000:8a2e:0390:7334 5678 3306\r\n"),
		[]byte("PROXY UNKNOWN 192.168.1.100 192.168.1.50 5678 3306\r\n"),
		[]byte("PROXY TCP 192.168.1.100 192.168.1.50 5678 3306 3307\r\n"),
		[]byte("PROXY MCP3 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
		encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000"),
		encodeProxyProtocolV2Header("tcp6", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:5678", "[2001:db8:85a3::8a2e:370:8000]:4000"),
	}
	for _, t := range tests {
		f.Add(t)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cc := &proxyProtocolConn{
			Conn: newMockBufferConnBytes(data, nil),
		}
		cc.readClientAddrBehindProxy(nil)
	})
}
