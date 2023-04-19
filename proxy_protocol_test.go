package proxyprotocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

type mockBufferConn struct {
	*bytes.Buffer
	raddr net.Addr
	Err   error
}

func newMockBufferConn(buffer *bytes.Buffer, raddr net.Addr) net.Conn {
	return &mockBufferConn{
		Buffer: buffer,
		raddr:  raddr,
		Err:    nil,
	}
}

func newMockBufferConnWithErr(buffer *bytes.Buffer, raddr net.Addr, err error) net.Conn {
	return &mockBufferConn{
		Buffer: buffer,
		raddr:  raddr,
		Err:    err,
	}
}

func newMockBufferConnBytes(buffer []byte, raddr net.Addr) *mockBufferConn {
	return &mockBufferConn{
		Buffer: bytes.NewBuffer(buffer),
		raddr:  raddr,
	}
}

func (c *mockBufferConn) Read(buf []byte) (int, error) {
	n, err := c.Buffer.Read(buf)
	if err == nil && c.Err != nil {
		return n, c.Err
	}
	return n, err
}

func (c *mockBufferConn) Close() error {
	return nil
}

func (c *mockBufferConn) RemoteAddr() net.Addr {
	if c.raddr != nil {
		return c.raddr
	}
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	return addr
}

func (c *mockBufferConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:4000")
	return addr
}

func (c *mockBufferConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *mockBufferConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *mockBufferConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func assertTrue(t *testing.T, val bool) {
	if !val {
		t.Errorf("Expect true but got: %v", val)
	}
}

func assertFalse(t *testing.T, val bool) {
	if val {
		t.Errorf("Expect false but got: %v", val)
	}
}

func assertNil(t *testing.T, val any) {
	isNil := val == nil || (reflect.ValueOf(val).Kind() == reflect.Ptr && reflect.ValueOf(val).IsNil())
	if !isNil {
		t.Errorf("Expect nil but got: %v", val)
	}
}

func assertEquals[T comparable](t *testing.T, val, expected T, comments ...any) {
	if val != expected {
		if len(comments) == 0 {
			t.Errorf("Expect:\n  `%v`\nbut got:\n  `%v`\n", expected, val)
		} else {
			t.Errorf(comments[0].(string), comments[1:]...)
		}
	}
}

func TestProxyProtocolConnCheckAllowed(t *testing.T) {
	l, _ := newListener(nil, "*", 5, false, false)
	raddr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.100:8080")
	assertTrue(t, l.checkAllowed(raddr))
	l, _ = newListener(nil, "192.168.1.0/24,192.168.2.0/24", 5, false, false)
	for _, ipstr := range []string{"192.168.1.100:8080", "192.168.2.100:8080"} {
		raddr, _ := net.ResolveTCPAddr("tcp4", ipstr)
		assertTrue(t, l.checkAllowed(raddr))
	}
	for _, ipstr := range []string{"192.168.3.100:8080", "192.168.4.100:8080"} {
		raddr, _ := net.ResolveTCPAddr("tcp4", ipstr)
		assertFalse(t, l.checkAllowed(raddr))
	}
}

func TestProxyProtocolConnMustNotReadAnyDataAfterCLRF(t *testing.T) {
	buffer := []byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data")
	conn := newMockBufferConn(bytes.NewBuffer(buffer), nil)

	l, _ := newListener(nil, "*", 5, false, false)
	wconn, err := l.createProxyProtocolConn(conn)
	assertNil(t, err)

	expectedString := "Other Data"
	buf := make([]byte, 10)
	n, _ := wconn.Read(buf)
	assertEquals(t, n, 10)
	assertEquals(t, string(buf[0:n]), expectedString)

	buffer = []byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data")
	conn = newMockBufferConn(bytes.NewBuffer(buffer), nil)
	wconn, err = l.createProxyProtocolConn(conn)
	assertNil(t, err)
	buf = make([]byte, 5)
	n, err = wconn.Read(buf)
	assertNil(t, err)
	assertEquals(t, n, 5)
	assertEquals(t, string(buf[0:n]), "Other")
	n, err = wconn.Read(buf)
	assertNil(t, err)
	assertEquals(t, n, 5)
	assertEquals(t, string(buf[0:n]), " Data")

	buffer = []byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data for a very long long long long long content")
	expectedString = "Other Data for a very long long long long long content"
	conn = newMockBufferConn(bytes.NewBuffer(buffer), nil)
	wconn, err = l.createProxyProtocolConn(conn)
	assertNil(t, err)
	buf = make([]byte, 1024)
	n, err = wconn.Read(buf)
	assertNil(t, err)
	assertEquals(t, string(buf[0:n]), expectedString)
}

func TestProxyProtocolV2ConnMustNotReadAnyDataAfterHeader(t *testing.T) {
	craddr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.51:8080")
	buffer := encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000")
	expectedString := "Other Data"
	buffer = append(buffer, []byte(expectedString)...)
	l, _ := newListener(nil, "*", 5, false, false)
	conn := newMockBufferConn(bytes.NewBuffer(buffer), craddr)
	wconn, err := l.createProxyProtocolConn(conn)
	buf := make([]byte, len(expectedString))
	n, err := wconn.Read(buf)
	assertNil(t, err)
	assertEquals(t, string(buf[0:n]), expectedString)
}

func TestProxyProtocolV2ConnMustNotReadAnyDataAfterHeaderAndTlvs(t *testing.T) {
	var (
		tlvData1 = append([]byte{0xE3, 0x00, 0x01}, make([]byte, 100)...)
	)
	tests := []struct {
		buffer []byte
		expect string
	}{
		{
			buffer: encodeProxyProtocolV2HeaderAndTlv("tcp4", "192.168.1.100:5678", "192.168.1.5:4000", tlvData1),
			expect: "Other Data",
		},
		{
			buffer: encodeHexString("0d0a0d0a000d0a515549540a21110054c0a82a54ac1f414fbffa0050030004a654259b04003e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			expect: "Other",
		},
		{
			buffer: encodeHexString("0d0a0d0a000d0a515549540a20000000"),
			expect: "Other Data",
		},
	}

	craddr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.51:8080")
	for _, test := range tests {
		buffer := test.buffer
		buffer = append(buffer, []byte(test.expect)...)
		l, _ := newListener(nil, "*", 5, false, false)
		conn := newMockBufferConn(bytes.NewBuffer(buffer), craddr)
		wconn, err := l.createProxyProtocolConn(conn)
		buf := make([]byte, len(test.expect))
		n, err := wconn.Read(buf)
		assertNil(t, err)
		assertEquals(t, string(buf[0:n]), test.expect)
	}
}

func TestProxyProtocolV1HeaderRead(t *testing.T) {
	buffer := []byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data")
	expectedString := "PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\n"
	conn := newMockBufferConn(bytes.NewBuffer(buffer), nil)
	wconn := &proxyProtocolConn{
		Conn:              conn,
		headerReadTimeout: 5,
	}
	ver, buf, err := wconn.readHeader()
	assertNil(t, err)
	assertEquals(t, ver, proxyProtocolV1)
	assertEquals(t, string(buf), expectedString)
}

func TestProxyProtocolV1ExtractClientIP(t *testing.T) {
	craddr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.51:8080")
	tests := []struct {
		buffer      []byte
		expectedIP  string
		expectedErr bool
	}{
		{
			buffer:      []byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
			expectedIP:  "192.168.1.100:5678",
			expectedErr: false,
		},
		{
			buffer:      []byte("PROXY UNKNOWN 192.168.1.100 192.168.1.50 5678 3306\r\n"),
			expectedIP:  "192.168.1.51:8080",
			expectedErr: false,
		},
		{
			buffer:      []byte("PROXY TCP 192.168.1.100 192.168.1.50 5678 3306 3307\r\n"),
			expectedIP:  "",
			expectedErr: true,
		},
		{
			buffer:      []byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306 jkasdjfkljaksldfjklajsdkfjsklafjldsafa"),
			expectedIP:  "",
			expectedErr: true,
		},
		{
			buffer:      []byte("PROXY TCP4 192.168.1.100 192.168.1.50 5678 3306785478934785738275489275843728954782598345"),
			expectedIP:  "",
			expectedErr: true,
		},
		{
			buffer:      []byte("PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 2001:0db8:85a3:0000:0000:8a2e:0390:7334 5678 3306\r\n"),
			expectedIP:  "[2001:db8:85a3::8a2e:370:7334]:5678",
			expectedErr: false,
		},
		{
			buffer:      []byte("this is a invalid header"),
			expectedIP:  "",
			expectedErr: true,
		},
		{
			buffer:      []byte("PROXY"),
			expectedIP:  "",
			expectedErr: true,
		},
		{
			buffer:      []byte("PROXY MCP3 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
			expectedIP:  "",
			expectedErr: true,
		},
		{
			buffer:      []byte("PROXY UNKNOWN\r\n"),
			expectedIP:  "192.168.1.51:8080",
			expectedErr: false,
		},
	}

	l, _ := newListener(nil, "*", 5, false, false)
	for _, test := range tests {
		conn := newMockBufferConn(bytes.NewBuffer(test.buffer), craddr)
		wconn, err := l.createProxyProtocolConn(conn)
		if err == nil {
			clientIP := wconn.RemoteAddr()
			if test.expectedErr {
				t.Errorf("Buffer: %s\nExpect Error", string(test.buffer))
			}
			assertEquals(t, clientIP.String(), test.expectedIP, "Buffer:%s\nExpect: %s Got: %s", string(test.buffer), test.expectedIP, clientIP.String())
		} else {
			if !test.expectedErr {
				t.Errorf("Buffer:%s\nExpect %s But got Error: %v", string(test.buffer), test.expectedIP, err)
			}
		}
	}
}

func encodeProxyProtocolV2Header(network, srcAddr, dstAddr string) []byte {
	saddr, _ := net.ResolveTCPAddr(network, srcAddr)
	daddr, _ := net.ResolveTCPAddr(network, dstAddr)
	buffer := make([]byte, 1024)
	copy(buffer, proxyProtocolV2Sig)
	// Command
	buffer[v2CmdPos] = 0x21
	// Famly
	if network == "tcp4" {
		buffer[v2FamlyPos] = 0x11
		binary.BigEndian.PutUint16(buffer[14:14+2], 12)
		copy(buffer[16:16+4], []byte(saddr.IP.To4()))
		copy(buffer[20:20+4], []byte(daddr.IP.To4()))
		binary.BigEndian.PutUint16(buffer[24:24+2], uint16(saddr.Port))
		binary.BigEndian.PutUint16(buffer[26:26+2], uint16(saddr.Port))
		return buffer[0:28]
	} else if network == "tcp6" {
		buffer[v2FamlyPos] = 0x21
		binary.BigEndian.PutUint16(buffer[14:14+2], 36)
		copy(buffer[16:16+16], []byte(saddr.IP.To16()))
		copy(buffer[32:32+16], []byte(daddr.IP.To16()))
		binary.BigEndian.PutUint16(buffer[48:48+2], uint16(saddr.Port))
		binary.BigEndian.PutUint16(buffer[50:50+2], uint16(saddr.Port))
		return buffer[0:52]
	}
	return buffer
}

func encodeProxyProtocolV2HeaderAndTlv(network, srcAddr, dstAddr string, tlv []byte) []byte {
	saddr, _ := net.ResolveTCPAddr(network, srcAddr)
	daddr, _ := net.ResolveTCPAddr(network, dstAddr)
	buffer := make([]byte, 1024)
	copy(buffer, proxyProtocolV2Sig)
	// Command
	buffer[v2CmdPos] = 0x21
	tlvLen := uint16(len(tlv))
	// Famly
	if network == "tcp4" {
		buffer[v2FamlyPos] = 0x11
		binary.BigEndian.PutUint16(buffer[14:14+2], 12+tlvLen)
		copy(buffer[16:16+4], []byte(saddr.IP.To4()))
		copy(buffer[20:20+4], []byte(daddr.IP.To4()))
		binary.BigEndian.PutUint16(buffer[24:24+2], uint16(saddr.Port))
		binary.BigEndian.PutUint16(buffer[26:26+2], uint16(saddr.Port))
		return append(buffer[0:28], tlv...)
	} else if network == "tcp6" {
		buffer[v2FamlyPos] = 0x21
		binary.BigEndian.PutUint16(buffer[14:14+2], 36+tlvLen)
		copy(buffer[16:16+16], []byte(saddr.IP.To16()))
		copy(buffer[32:32+16], []byte(daddr.IP.To16()))
		binary.BigEndian.PutUint16(buffer[48:48+2], uint16(saddr.Port))
		binary.BigEndian.PutUint16(buffer[50:50+2], uint16(saddr.Port))
		return append(buffer[0:52], tlv...)
	}
	return append(buffer, tlv...)
}

func encodeHexString(data string) []byte {
	ret, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	return ret
}

func TestProxyProtocolV2HeaderRead(t *testing.T) {
	var (
		tlvData1 = append([]byte{0xE3, 0x00, 0x01}, make([]byte, 100)...)
	)
	craddr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.51:8080")
	tests := []struct {
		buffer     []byte
		expectedIP string
	}{
		{
			buffer:     encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000"),
			expectedIP: "192.168.1.100:5678",
		},
		{
			buffer:     encodeProxyProtocolV2Header("tcp6", "[2001:db8:85a3::8a2e:370:7334]:5678", "[2001:db8:85a3::8a2e:370:8000]:4000"),
			expectedIP: "[2001:db8:85a3::8a2e:370:7334]:5678",
		},
		{
			buffer:     encodeProxyProtocolV2HeaderAndTlv("tcp4", "192.168.1.100:5678", "192.168.1.5:4000", tlvData1),
			expectedIP: "192.168.1.100:5678",
		},
		{
			buffer:     encodeHexString("0d0a0d0a000d0a515549540a21110054c0a82a54ac1f414fbffa0050030004a654259b04003e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			expectedIP: "192.168.42.84:49146",
		},
		{
			buffer:     encodeHexString("0d0a0d0a000d0a515549540a20000000"),
			expectedIP: "192.168.1.51:8080",
		},
	}

	l, _ := newListener(nil, "*", 5, false, false)
	for _, test := range tests {
		conn := newMockBufferConn(bytes.NewBuffer(test.buffer), craddr)
		wconn, err := l.createProxyProtocolConn(conn)
		if err != nil {
			t.Errorf("Got Error: %v", err)
		} else {
			clientIP := wconn.RemoteAddr()
			if err == nil {
				assertEquals(t, clientIP.String(), test.expectedIP, "Buffer:%v\nExpect: %s Got: %s", test.buffer, test.expectedIP, clientIP.String())
			} else {
				t.Errorf("Buffer:%v\nExpect: %s Got Error: %v", test.buffer, test.expectedIP, err)
			}
		}
	}
}

func TestProxyProtocolV2HeaderReadLocalCommand(t *testing.T) {
	craddr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.51:8080")
	buffer := encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000")
	buffer[v2CmdPos] = 0x20
	l, _ := newListener(nil, "*", 5, false, false)
	conn := newMockBufferConn(bytes.NewBuffer(buffer), craddr)
	wconn, err := l.createProxyProtocolConn(conn)
	clientIP := wconn.RemoteAddr()
	assertNil(t, err)
	assertEquals(t, clientIP.String(), craddr.String(), "Buffer:%v\nExpected: %s Got: %s", buffer, craddr.String(), clientIP.String())
}

func TestProxyProtocolListenerReadHeaderTimeout(t *testing.T) {
	addr := "127.0.0.1:18080"
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		l, err := net.Listen("tcp", addr)
		assertNil(t, err)
		ppl, err := NewListener(l, "*", 1, false)
		assertNil(t, err)
		defer ppl.Close()
		wg.Done()
		conn, err := ppl.Accept()
		assertNil(t, conn)
		assertEquals(t, err.Error(), ErrHeaderReadTimeout.Error())
	}()

	wg.Wait()
	conn, err := net.Dial("tcp", addr)
	assertNil(t, err)
	time.Sleep(2 * time.Second)
	conn.Close()
}

func TestProxyProtocolListenerProxyNotAllowed(t *testing.T) {
	addr := "127.0.0.1:18081"
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		l, err := net.Listen("tcp", addr)
		assertNil(t, err)
		ppl, err := NewListener(l, "192.168.1.1", 1, false)
		assertNil(t, err)
		defer ppl.Close()
		wg.Done()
		conn, err := ppl.Accept()
		assertNil(t, err)
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	wg.Wait()
	conn, err := net.Dial("tcp", addr)
	assertNil(t, err)
	time.Sleep(2 * time.Second)
	conn.Close()
}

func TestProxyProtocolListenerCloseInOtherGoroutine(t *testing.T) {
	addr := "127.0.0.1:18082"
	l, err := net.Listen("tcp", addr)
	assertNil(t, err)
	ppl, err := NewListener(l, "*", 1, false)
	assertNil(t, err)
	go func() {
		conn, err := ppl.Accept()
		assertNil(t, conn)
		opErr, ok := err.(*net.OpError)
		assertTrue(t, ok)
		assertEquals(t, opErr.Err.Error(), "use of closed network connection")
	}()

	time.Sleep(1 * time.Second)
	ppl.Close()
	time.Sleep(2 * time.Second)
}

func TestProxyProtocolLazyMode(t *testing.T) {
	var (
		tlvData1 = append([]byte{0xE3, 0x00, 0x01}, make([]byte, 100)...)
	)
	craddr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.51:8080")
	tests := []struct {
		buffer     []byte
		expectData string
		expectIP   string
		expectErr  bool
	}{
		{
			buffer:     encodeProxyProtocolV2HeaderAndTlv("tcp4", "192.168.1.100:5678", "192.168.1.5:4000", tlvData1),
			expectData: "Other Data",
			expectIP:   "192.168.1.100:5678",
			expectErr:  false,
		},
		{
			buffer:     encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000"),
			expectData: "Other Data",
			expectIP:   "192.168.1.100:5678",
			expectErr:  false,
		},
		{
			buffer:     encodeHexString("0d0a0d0a000d0a515549540a21110054c0a82a54ac1f414fbffa0050030004a654259b04003e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			expectData: "Other",
			expectIP:   "192.168.42.84:49146",
			expectErr:  false,
		},
		{
			buffer:     encodeHexString("0d0a0d0a000d0a515549540a20000000"),
			expectData: "Other Data",
			expectIP:   "192.168.1.51:8080",
			expectErr:  false,
		},
		{
			buffer:     []byte("PROXY MCP3 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
			expectData: "Other Data",
			expectIP:   "",
			expectErr:  true,
		},
	}
	l, _ := newListener(nil, "*", 5, true, false)
	for _, test := range tests {
		buffer := test.buffer
		buffer = append(buffer, []byte(test.expectData)...)
		conn := newMockBufferConn(bytes.NewBuffer(buffer), craddr)
		wconn, err := l.createProxyProtocolConn(conn)
		clientIP := wconn.RemoteAddr()
		assertEquals(t, clientIP.String(), craddr.String(), "Buffer:%s\nExpect: %s Got: %s", string(buffer), craddr.String(), clientIP.String())

		buf := make([]byte, len(test.expectData))
		n, err := wconn.Read(buf)
		if test.expectErr {
			if err == nil {
				t.Errorf("Buffer: %s\nExpect Error", string(buffer))
			}
		} else {
			assertNil(t, err)
			assertEquals(t, string(buf[0:n]), test.expectData)
			clientIP = wconn.RemoteAddr()
			assertEquals(t, clientIP.String(), test.expectIP, "Buffer:%s\nExpect: %s Got: %s", string(buffer), test.expectIP, clientIP.String())
		}
	}
}

func TestProxyProtocolLazyModeFallback(t *testing.T) {
	tlvData1 := append([]byte{0xE3, 0x00, 0x01}, make([]byte, 100)...)
	craddr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.51:8080")
	tests := []struct {
		buffer     []byte
		expectData string
		expectIP   string
		expectErr  bool
	}{
		{
			buffer:     []byte("Raw Connection Other Data"),
			expectData: "Raw Connection Other Data",
			expectIP:   "192.168.1.51:8080",
			expectErr:  false,
		},
		{
			buffer:     append(encodeProxyProtocolV2HeaderAndTlv("tcp4", "192.168.1.100:5678", "192.168.1.5:4000", tlvData1), []byte("Other Data")...),
			expectData: "Other Data",
			expectIP:   "192.168.1.100:5678",
			expectErr:  false,
		},
		{
			buffer:     append(encodeProxyProtocolV2Header("tcp4", "192.168.1.100:5678", "192.168.1.5:4000"), []byte("Other Data")...),
			expectData: "Other Data",
			expectIP:   "192.168.1.100:5678",
			expectErr:  false,
		},
		{
			buffer:     []byte("PROXY MCP3 192.168.1.100 192.168.1.50 5678 3306\r\nOther Data"),
			expectData: "Other Data",
			expectIP:   "",
			expectErr:  true,
		},
		{
			buffer:     []byte("Some bad data"),
			expectData: "Some bad data",
			expectIP:   "192.168.1.51:8080",
			expectErr:  false,
		},
		{
			buffer:     []byte("Other Data for a very long long long long long long long long long long long long long long content"),
			expectData: "Other Data for a very long long long long long long long long long long long long long long content",
			expectIP:   "192.168.1.51:8080",
			expectErr:  false,
		},
	}
	l, _ := newListener(nil, "*", 5, true, true)
	for _, test := range tests {
		buffer := test.buffer
		conn := newMockBufferConn(bytes.NewBuffer(buffer), craddr)
		wconn, err := l.createProxyProtocolConn(conn)
		clientIP := wconn.RemoteAddr()
		assertEquals(t, clientIP.String(), craddr.String(), "Buffer:%s\nExpect: %s Got: %s", string(buffer), craddr.String(), clientIP.String())
		buf := make([]byte, len(test.expectData))
		n, err := wconn.Read(buf)
		if test.expectErr {
			if err == nil {
				t.Errorf("Buffer: %s\nExpect Error", string(buffer))
			}
		} else {
			assertNil(t, err)
			assertEquals(t, string(buf[0:n]), test.expectData)
			clientIP = wconn.RemoteAddr()
			assertEquals(t, clientIP.String(), test.expectIP, "Buffer:%s\nExpect: %s Got: %s", string(buffer), test.expectIP, clientIP.String())
		}
	}
}

func TestProxyProtocolListenerReadTimeoutWithLazyMode(t *testing.T) {
	addr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.1:8080")
	l, _ := newListener(nil, "*", 5, true, true)
	conn := newMockBufferConn(bytes.NewBufferString(""), addr)
	wconn, err := l.createProxyProtocolConn(conn)
	if err != nil {
		t.Errorf("Got Error: %v", err)
	} else {
		buf := make([]byte, 4096)
		_, err = wconn.Read(buf)
		if err == nil {
			t.Fatalf("Should got error")
		}
		if err == ErrHeaderReadTimeout {
			t.Fatalf("Should not return header read timeout error")
		}
		if err != io.EOF {
			t.Fatalf("Expect EOF error but got: %v", err)
		}
	}
}

func TestFallbackWithConnectionReadError(t *testing.T) {
	addr, _ := net.ResolveTCPAddr("tcp4", "192.168.1.1:8080")
	l, _ := newListener(nil, "*", 5, true, true)
	conn := newMockBufferConnWithErr(bytes.NewBufferString("test"), addr, io.EOF)
	wconn, _ := l.createProxyProtocolConn(conn)
	buf := make([]byte, 4096)
	n, err := wconn.Read(buf)
	if err == nil {
		t.Fatalf("Should got error")
	}
	if err != io.EOF {
		t.Fatalf("Expect EOF error but got: %v", err)
	}
	if n != 4 || string(buf[0:n]) != "test" {
		t.Fatalf("Buffer expect [test] but not same")
	}
}
