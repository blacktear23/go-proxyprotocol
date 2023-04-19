package proxyprotocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"errors"
)

// Ref: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt .
const (
	proxyProtocolV1MaxHeaderLen = 108
	unknownProtocol             = 0
	proxyProtocolV1             = 1
	proxyProtocolV2             = 2
	v2CmdPos                    = 12
	v2FamlyPos                  = 13
	v2LenPos                    = 14
	v2AddrsPos                  = 16
)

var (
	ErrProxyProtocolV1HeaderInvalid = errors.New("PROXY Protocol v1 header is invalid")
	ErrProxyProtocolV2HeaderInvalid = errors.New("PROXY Protocol v2 header is invalid")
	ErrProxyProtocolInvalid         = errors.New("Invalid PROXY Protocol Header")
	ErrHeaderReadTimeout            = errors.New("Header read timeout")
	proxyProtocolV2Sig              = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	proxyProtocolV1Sig              = []byte("PROXY")

	_ net.Conn     = &proxyProtocolConn{}
	_ net.Listener = &proxyProtocolListener{}
)

type connErr struct {
	conn net.Conn
	err  error
}

type proxyProtocolListener struct {
	listener          net.Listener
	allowedNets       []*net.IPNet
	runningFlag       int32
	headerReadTimeout int // Unit is second
	acceptQueue       chan *connErr
	allowAll          bool
	lazyMode          bool
	fallbackable      bool
}

func IsProxyProtocolError(err error) bool {
	return err == ErrProxyProtocolV1HeaderInvalid ||
		err == ErrProxyProtocolV2HeaderInvalid ||
		err == ErrHeaderReadTimeout ||
		err == ErrProxyProtocolInvalid
}

// Create new PROXY protocol listener
// * listener is basic listener for TCP
// * allowedIPs is protocol allowed addresses or CIDRs split by `,` if use '*' means allow any address
// * headerReadTimeout is timeout for PROXY protocol header read
func NewListener(listener net.Listener, allowedIPs string, headerReadTimeout int, fallbackable bool) (net.Listener, error) {
	ppl, err := newListener(listener, allowedIPs, headerReadTimeout, false, fallbackable)
	if err == nil {
		go ppl.acceptLoop()
	}
	return ppl, err
}

// Create new PROXY protocol listener for lazy mode. Lazy mode means PROXY protocol header will be processed at first
// `Read` call.
// * listener is basic listener for TCP
// * allowedIPs is protocol allowed addresses or CIDRs split by `,` if use '*' means allow any address
// * headerReadTimeout is timeout for PROXY protocol header read
func NewLazyListener(listener net.Listener, allowedIPs string, headerReadTimeout int, fallbackable bool) (net.Listener, error) {
	ppl, err := newListener(listener, allowedIPs, headerReadTimeout, true, fallbackable)
	if err == nil {
		go ppl.acceptLoop()
	}
	return ppl, err
}

func newListener(listener net.Listener, allowedIPs string, headerReadTimeout int, lazyMode bool, fallbackable bool) (*proxyProtocolListener, error) {
	allowAll := false
	allowedNets := []*net.IPNet{}
	if allowedIPs == "*" {
		allowAll = true
	} else {
		for _, aip := range strings.Split(allowedIPs, ",") {
			saip := strings.TrimSpace(aip)
			_, ipnet, err := net.ParseCIDR(saip)
			if err == nil {
				allowedNets = append(allowedNets, ipnet)
				continue
			}
			_, ipnet, err = net.ParseCIDR(saip + "/32")
			if err != nil {
				return nil, err
			}
			allowedNets = append(allowedNets, ipnet)
		}
	}
	return &proxyProtocolListener{
		listener:          listener,
		allowAll:          allowAll,
		allowedNets:       allowedNets,
		headerReadTimeout: headerReadTimeout,
		acceptQueue:       make(chan *connErr, 1),
		runningFlag:       1,
		lazyMode:          lazyMode,
		fallbackable:      fallbackable,
	}, nil
}

// Check remote address is allowed
func (l *proxyProtocolListener) checkAllowed(raddr net.Addr) bool {
	if l.allowAll {
		return true
	}
	taddr, ok := raddr.(*net.TCPAddr)
	if !ok {
		return false
	}
	cip := taddr.IP
	for _, ipnet := range l.allowedNets {
		if ipnet.Contains(cip) {
			return true
		}
	}
	return false
}

// Create proxyProtocolConn instance
func (l *proxyProtocolListener) createProxyProtocolConn(conn net.Conn) (*proxyProtocolConn, error) {
	ppconn := &proxyProtocolConn{
		Conn:              conn,
		headerReadTimeout: l.headerReadTimeout,
		lazyMode:          l.lazyMode,
		headerReaded:      false,
		fallbackable:      l.fallbackable,
	}
	if !l.lazyMode {
		err := ppconn.readClientAddrBehindProxy(conn.RemoteAddr())
		if err != nil {
			ppconn.Close()
			return nil, err
		}
	} else {
		ppconn.clientIP = conn.RemoteAddr()
	}
	return ppconn, nil
}

func (l *proxyProtocolListener) running() bool {
	r := atomic.LoadInt32(&l.runningFlag)
	return r == 1
}

func (l *proxyProtocolListener) acceptLoop() {
	for l.running() {
		conn, err := l.listener.Accept()
		if err != nil {
			l.acceptQueue <- &connErr{conn, err}
		} else if !l.checkAllowed(conn.RemoteAddr()) && l.running() {
			// do not parse proxy protocol header
			l.acceptQueue <- &connErr{conn, nil}
		} else {
			go l.wrapConn(conn)
		}
	}
}

func (l *proxyProtocolListener) wrapConn(conn net.Conn) {
	wconn, err := l.createProxyProtocolConn(conn)
	if l.running() {
		l.acceptQueue <- &connErr{wconn, err}
	} else {
		wconn.Close()
	}
}

// Accept new connection
// You should check error instead of panic it.
// As PROXY protocol SPEC wrote, if invalid PROXY protocol header
// received, or valid header received but connection's address not
// allowed, Accept function will return an error and close this connection.
func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	ce := <-l.acceptQueue
	if opErr, ok := ce.err.(*net.OpError); ok {
		if opErr.Err.Error() == "use of closed network connection" {
			close(l.acceptQueue)
		}
	}
	return ce.conn, ce.err
}

// Close listener
func (l *proxyProtocolListener) Close() error {
	atomic.SwapInt32(&l.runningFlag, 0)
	err := l.listener.Close()
	return err
}

// Get listener's address
func (l *proxyProtocolListener) Addr() net.Addr {
	return l.listener.Addr()
}

type proxyProtocolConn struct {
	net.Conn
	headerReadTimeout  int
	clientIP           net.Addr
	exceedBuffer       []byte
	exceedBufferStart  int
	exceedBufferLen    int
	exceedBufferReaded bool
	lazyMode           bool
	headerReaded       bool
	fallbackable       bool
}

func (c *proxyProtocolConn) readClientAddrBehindProxy(connRemoteAddr net.Addr) error {
	return c.parseHeader(connRemoteAddr)
}

func (c *proxyProtocolConn) parseHeader(connRemoteAddr net.Addr) error {
	ver, buffer, err := c.readHeader()
	if err != nil {
		// If unknown protocol and fallbackable it should
		// fill the readed buffer to exceed buffer
		if ver == unknownProtocol && c.fallbackable {
			c.exceedBuffer = buffer
			c.exceedBufferLen = len(buffer)
			c.headerReaded = true
		}
		return err
	}
	switch ver {
	case proxyProtocolV1:
		raddr, v1err := c.extractClientIPV1(buffer, connRemoteAddr)
		if v1err != nil {
			return v1err
		}
		c.clientIP = raddr
		c.headerReaded = true
		return nil
	case proxyProtocolV2:
		raddr, v2err := c.extraceClientIPV2(buffer, connRemoteAddr)
		if v2err != nil {
			return v2err
		}
		c.clientIP = raddr
		c.headerReaded = true
		return nil
	case unknownProtocol:
		if c.fallbackable {
			c.exceedBuffer = buffer
			c.exceedBufferLen = len(buffer)
			c.headerReaded = true
			return nil
		}
		return ErrProxyProtocolInvalid
	default:
		panic("Should not come here")
	}
}

func (c *proxyProtocolConn) extractClientIPV1(buffer []byte, connRemoteAddr net.Addr) (net.Addr, error) {
	header := string(buffer)
	parts := strings.Split(header, " ")
	if len(parts) != 6 {
		if len(parts) > 1 && parts[1] == "UNKNOWN\r\n" {
			return connRemoteAddr, nil
		}
		return nil, ErrProxyProtocolV1HeaderInvalid
	}
	clientIPStr := parts[2]
	clientPortStr := parts[4]
	iptype := parts[1]
	ip := net.ParseIP(clientIPStr)
	if ip == nil {
		return nil, ErrProxyProtocolV1HeaderInvalid
	}
	port, err := strconv.Atoi(clientPortStr)
	if err != nil {
		return nil, ErrProxyProtocolV1HeaderInvalid
	}
	if port <= 0 || port > 65535 {
		return nil, ErrProxyProtocolV1HeaderInvalid
	}
	switch iptype {
	case "TCP4", "TCP6":
		return &net.TCPAddr{
			IP:   ip,
			Port: port,
		}, nil
	case "UNKNOWN":
		return connRemoteAddr, nil
	default:
		return nil, ErrProxyProtocolV1HeaderInvalid
	}
}

func (c *proxyProtocolConn) extraceClientIPV2(buffer []byte, connRemoteAddr net.Addr) (net.Addr, error) {
	verCmd := buffer[v2CmdPos]
	famly := buffer[v2FamlyPos]
	switch verCmd & 0x0F {
	case 0x01: /* PROXY command */
		switch famly {
		case 0x11: /* TCPv4 */
			srcAddrV4 := net.IP(buffer[v2AddrsPos : v2AddrsPos+4])
			srcPortV4 := binary.BigEndian.Uint16(buffer[v2AddrsPos+8 : v2AddrsPos+10])
			return &net.TCPAddr{
				IP:   srcAddrV4,
				Port: int(srcPortV4),
			}, nil
		case 0x21: /* TCPv6 */
			srcAddrV6 := net.IP(buffer[v2AddrsPos : v2AddrsPos+16])
			srcPortV6 := binary.BigEndian.Uint16(buffer[v2AddrsPos+32 : v2AddrsPos+34])
			return &net.TCPAddr{
				IP:   srcAddrV6,
				Port: int(srcPortV6),
			}, nil
		default:
			// unsupported protocol, keep local connection address
			return connRemoteAddr, nil
		}
	case 0x00: /* LOCAL command */
		// keep local connection address for LOCAL
		return connRemoteAddr, nil
	default:
		// not a supported command
		return nil, ErrProxyProtocolV2HeaderInvalid
	}
}

// Get client address
func (c *proxyProtocolConn) RemoteAddr() net.Addr {
	return c.clientIP
}

// Read received data
func (c *proxyProtocolConn) Read(buffer []byte) (int, error) {
	if c.lazyMode && !c.headerReaded {
		err := c.parseHeader(c.clientIP)
		if err != nil {
			if c.fallbackable {
				// If fallbackable it should fill the buffer that
				// readed by parse header step.
				maxn := len(buffer)
				if c.exceedBufferLen < maxn {
					maxn = c.exceedBufferLen
				}
				copy(buffer[0:], c.exceedBuffer[0:maxn])
				return maxn, err
			}
			return 0, err
		}
	}
	if c.exceedBufferReaded {
		return c.Conn.Read(buffer)
	}
	if c.exceedBufferLen == 0 || c.exceedBufferStart >= c.exceedBufferLen {
		c.exceedBufferReaded = true
		return c.Conn.Read(buffer)
	}

	buflen := len(buffer)
	nExceedRead := c.exceedBufferLen - c.exceedBufferStart
	// buffer length is less or equals than exceedBuffer length
	if nExceedRead >= buflen {
		copy(buffer[0:], c.exceedBuffer[c.exceedBufferStart:c.exceedBufferStart+buflen])
		c.exceedBufferStart += buflen
		return buflen, nil
	}
	// buffer length is great than exceedBuffer length, just return the exceed buffer data
	copy(buffer[0:nExceedRead], c.exceedBuffer[c.exceedBufferStart:])
	c.exceedBufferStart = c.exceedBufferLen
	c.exceedBufferReaded = true
	return nExceedRead, nil
}

func (c *proxyProtocolConn) readHeader() (int, []byte, error) {
	buf := make([]byte, proxyProtocolV1MaxHeaderLen)
	// Should not update read timeout when in lazy mode
	if !c.lazyMode {
		// This mean all header data should be read in headerReadTimeout seconds.
		c.Conn.SetReadDeadline(time.Now().Add(time.Duration(c.headerReadTimeout) * time.Second))
		// When function return clean read deadline.
		defer func() {
			c.Conn.SetReadDeadline(time.Time{})
		}()
	}
	n, err := c.Conn.Read(buf)
	if err != nil {
		if c.lazyMode {
			return unknownProtocol, buf[0:n], err
		}
		return unknownProtocol, nil, ErrHeaderReadTimeout
	}
	if n >= 16 {
		// Chech Proxy Protocol V2 header
		if bytes.Equal(buf[0:12], proxyProtocolV2Sig) && (buf[v2CmdPos]&0xF0) == 0x20 {
			endPos := 16 + int(binary.BigEndian.Uint16(buf[v2LenPos:v2LenPos+2]))
			if n < endPos {
				// With TLV should skip those bytes
				moreBytes := endPos - n
				skipBuf := make([]byte, moreBytes)

				// Should not update read timeout when in lazy mode
				if !c.lazyMode {
					c.Conn.SetReadDeadline(time.Now().Add(time.Duration(c.headerReadTimeout) * time.Second))
				}

				_, err = io.ReadFull(c.Conn, skipBuf)
				if err != nil {
					return unknownProtocol, nil, ErrHeaderReadTimeout
				}
				return proxyProtocolV2, buf, nil
			}
			if n > endPos {
				c.exceedBuffer = buf[endPos:]
				c.exceedBufferLen = n - endPos
			}
			return proxyProtocolV2, buf[0:endPos], nil
		}
	}
	if n >= 5 {
		// Chech Proxy Protocol V1 header
		if bytes.Equal(buf[0:5], proxyProtocolV1Sig) {
			pos := bytes.IndexByte(buf, byte(10))
			if pos == -1 {
				return unknownProtocol, nil, ErrProxyProtocolV1HeaderInvalid
			}
			if buf[pos-1] != byte(13) {
				return unknownProtocol, nil, ErrProxyProtocolV1HeaderInvalid
			}
			endPos := pos
			if n > endPos {
				c.exceedBuffer = buf[endPos+1:]
				c.exceedBufferLen = n - endPos - 1
			}
			return proxyProtocolV1, buf[0 : endPos+1], nil
		}
	}
	// Unknown protocol
	return unknownProtocol, buf[0:n], nil
}
