// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shadowsocks

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	logging "github.com/op/go-logging"
)

// Simulates receiving invalid TCP connection attempts on a server with 100 ciphers.
func BenchmarkTCPFindCipherFail(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	logging.SetLevel(logging.INFO, "")
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}

	cipherList, err := MakeTestCiphers(100)
	if err != nil {
		b.Fatal(err)
	}
	testPayload := MakeTestPayload(50)
	for n := 0; n < b.N; n++ {
		go func() {
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				b.Fatalf("Failed to dial %v: %v", listener.Addr(), err)
			}
			conn.Write(testPayload)
			conn.Close()
		}()
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			b.Fatalf("AcceptTCP failed: %v", err)
		}
		b.StartTimer()
		findAccessKey(clientConn, cipherList)
		b.StopTimer()
	}
}

// Fake DuplexConn
// 1-way pipe, representing the upstream flow as seen by the server.
type conn struct {
	onet.DuplexConn
	clientAddr net.Addr
	reader     io.ReadCloser
	writer     io.WriteCloser
}

func (c *conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	// Any downstream data is ignored.
	return len(b), nil
}

func (c *conn) Close() error {
	e1 := c.reader.Close()
	e2 := c.writer.Close()
	if e1 != nil {
		return e1
	}
	return e2
}

func (c *conn) LocalAddr() net.Addr {
	return nil
}

func (c *conn) RemoteAddr() net.Addr {
	return c.clientAddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return errors.New("SetDeadline is not supported")
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return errors.New("SetDeadline is not supported")
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return errors.New("SetDeadline is not supported")
}

func (c *conn) CloseRead() error {
	return c.reader.Close()
}

func (c *conn) CloseWrite() error {
	return nil
}

// Simulates receiving valid TCP connection attempts from 100 different users,
// each with their own cipher and their own IP address.
func BenchmarkTCPFindCipherRepeat(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	logging.SetLevel(logging.INFO, "")

	const numCiphers = 100 // Must be <256
	cipherList, err := MakeTestCiphers(numCiphers)
	if err != nil {
		b.Fatal(err)
	}
	cipherEntries := [numCiphers]*CipherEntry{}
	for cipherNumber, element := range cipherList.SafeSnapshotForClientIP(nil) {
		cipherEntries[cipherNumber] = element.Value.(*CipherEntry)
	}
	for n := 0; n < b.N; n++ {
		cipherNumber := byte(n % numCiphers)
		reader, writer := io.Pipe()
		addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, cipherNumber), Port: 54321}
		c := conn{clientAddr: addr, reader: reader, writer: writer}
		cipher := cipherEntries[cipherNumber].Cipher
		go NewShadowsocksWriter(writer, cipher).Write(MakeTestPayload(50))
		b.StartTimer()
		_, _, err := findAccessKey(&c, cipherList)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		c.Close()
	}
}

func TestTCPProbe49(t *testing.T) {
	probeExpectTimeout(t, 49)
}

// func TestTCPProbe50(t *testing.T) {
// 	probeExpectTimeout(t, 50)
// }

// // func TestTCPProbe51(t *testing.T) {
// // 	probe(t, 51)
// // }

// func probeExpectEOF(t *testing.T, payloadSize int) {

// }

func probeExpectTimeout(t *testing.T, payloadSize int) {
	s := setupProbe(t, payloadSize)
	err := (*s).Start()
	if cErr, ok := err.(*onet.ConnectionError); ok && cErr.IsTimeout() {
		return
	} else {
		t.Fatalf("Unexpected error %v", err)
	}
}

func setupProbe(t *testing.T, payloadSize int) *TCPService {
	timeout := 500 * time.Millisecond
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	cipherList, err := MakeTestCiphers(5)
	if err != nil {
		t.Fatal(err)
	}
	testPayload := MakeTestPayload(payloadSize)
	s := NewTCPService(listener, &cipherList, metrics.NewShadowsocksMetrics(nil), timeout)

	go func() {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("Failed to dial %v: %v", listener.Addr(), err)
		}
		conn.Write(testPayload)
	}()

	defer func() {
		time.AfterFunc(timeout+250*time.Millisecond, func() {
			s.Stop()
		})
	}()

	return &s
}
