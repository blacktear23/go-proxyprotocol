package proxyprotocol

import "testing"

func BenchmarkHeaderV1Parser(b *testing.B) {
	cc := &proxyProtocolConn{
		Conn: nil,
	}
	tests := [][]byte{
		[]byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
		[]byte("PROXY TCP 192.168.1.100 192.168.1.50 5678 3306 3307\r\n"),
		[]byte("PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 2001:0db8:85a3:0000:0000:8a2e:0390:7334 5678 3306\r\n"),
		[]byte("PROXY UNKNOWN\r\n"),
	}
	nt := len(tests)
	for i := 0; i < b.N; i++ {
		cc.extractClientIPV1(tests[i%nt], nil)
	}
}

func BenchmarkHeaderV2Parser(b *testing.B) {
	cc := &proxyProtocolConn{
		Conn: nil,
	}
	tests := [][]byte{
		encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000"),
		encodeProxyProtocolV2Header("tcp6", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:5678", "[2001:db8:85a3::8a2e:370:8000]:4000"),
	}
	nt := len(tests)
	for i := 0; i < b.N; i++ {
		cc.extraceClientIPV2(tests[i%nt], nil)
	}
}

func BenchmarkProtocolVersionTest(b *testing.B) {
	tests := [][]byte{
		[]byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
		[]byte("PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 2001:0db8:85a3:0000:0000:8a2e:0390:7334 5678 3306\r\n"),
		encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000"),
		encodeProxyProtocolV2Header("tcp6", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:5678", "[2001:db8:85a3::8a2e:370:8000]:4000"),
	}
	nt := len(tests)
	for i := 0; i < b.N; i++ {
		data := tests[i%nt]
		cc := &proxyProtocolConn{
			Conn: newMockBufferConnBytes(data, nil),
		}
		cc.readHeader()
	}
}

func BenchmarkParseHeaderMix(b *testing.B) {
	tests := [][]byte{
		[]byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
		[]byte("PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 2001:0db8:85a3:0000:0000:8a2e:0390:7334 5678 3306\r\n"),
		encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000"),
		encodeProxyProtocolV2Header("tcp6", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:5678", "[2001:db8:85a3::8a2e:370:8000]:4000"),
	}
	nt := len(tests)
	for i := 0; i < b.N; i++ {
		data := tests[i%nt]
		cc := &proxyProtocolConn{
			Conn: newMockBufferConnBytes(data, nil),
		}
		cc.readClientAddrBehindProxy(nil)
	}
}

func BenchmarkParseHeaderV1(b *testing.B) {
	tests := [][]byte{
		[]byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
		[]byte("PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 2001:0db8:85a3:0000:0000:8a2e:0390:7334 5678 3306\r\n"),
	}
	nt := len(tests)
	for i := 0; i < b.N; i++ {
		data := tests[i%nt]
		cc := &proxyProtocolConn{
			Conn: newMockBufferConnBytes(data, nil),
		}
		cc.readClientAddrBehindProxy(nil)
	}
}

func BenchmarkParseHeaderV2(b *testing.B) {
	tests := [][]byte{
		encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000"),
		encodeProxyProtocolV2Header("tcp6", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:5678", "[2001:db8:85a3::8a2e:370:8000]:4000"),
	}
	nt := len(tests)
	for i := 0; i < b.N; i++ {
		data := tests[i%nt]
		cc := &proxyProtocolConn{
			Conn: newMockBufferConnBytes(data, nil),
		}
		cc.readClientAddrBehindProxy(nil)
	}
}
