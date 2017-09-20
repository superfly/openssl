// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

// ListenAndServeTLS will take an http.Handler and serve it using OpenSSL over
// the given tcp address, configured to use the provided cert and key files.
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler) error {
	return ServerListenAndServeTLS(&http.Server{Addr: addr, Handler: handler}, certFile, keyFile)
}

// ServerListenAndServeTLS will take an http.Server and serve it using OpenSSL
// configured to use the provided cert and key files.
func ServerListenAndServeTLS(srv *http.Server, certFile, keyFile string) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ctx, err := NewCtxFromFiles(certFile, keyFile)
	if err != nil {
		return err
	}

	l, err := Listen("tcp", addr, ctx)
	if err != nil {
		return err
	}

	return srv.Serve(l)
}

// HTTP2Handler wraps a handler to serve http2
func HTTP2Handler(h http.Handler) http.Handler {
	return &http2Handler{
		handler: h,
	}
}

type http2Handler struct {
	handler http.Handler
}

func (h *http2Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == "PRI" && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		if hijacker, ok := w.(http.Hijacker); ok {
			body := "SM\r\n\r\n"
			con, rw, err := hijacker.Hijack()
			defer con.Close()
			if err != nil {
			} else if n, err := io.MultiReader(req.Body, rw).Read([]byte(body)); n != len(body) {
				fmt.Printf("read did not match body len: %d, err: %s\n", n, err)
			} else {
				wrap := io.MultiReader(bytes.NewBuffer([]byte(http2.ClientPreface)), rw)
				nc := &h2conn{
					Conn:   con,
					Writer: rw.Writer,
					Reader: wrap,
				}
				h2s := &http2.Server{
					NewWriteScheduler: func() http2.WriteScheduler { return http2.NewPriorityWriteScheduler(nil) },
				}
				h2s.ServeConn(nc, &http2.ServeConnOpts{Handler: h.handler})
				return
			}
			http.Error(w, "Server could not handle the request.", http.StatusMethodNotAllowed)
			return
		}
	}
	h.handler.ServeHTTP(w, req)
}

type h2conn struct {
	net.Conn // embed for methods
	io.Reader
	*bufio.Writer
	vacuumAck bool
	buf       []byte
}

func (c h2conn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

func (c *h2conn) Write(b []byte) (int, error) {
	if c.vacuumAck {
		c.buf = append(c.buf, b...)
		for c.vacuumAck {
			if len(c.buf) < 9 {
				return len(b), nil // just buffered into c.buf
			}
			fh, err := http2.ReadFrameHeader(bytes.NewBuffer(c.buf))
			if err != nil {
				return 0, err // in case frame was broken
			} else if uint32(len(c.buf)) < 9+fh.Length {
				return len(b), nil // just buffered into c.buf
			}
			buf := c.buf[:9+fh.Length]
			c.buf = c.buf[9+fh.Length:]
			if http2.FrameSettings == fh.Type && fh.Flags.Has(http2.FlagSettingsAck) {
				c.vacuumAck = false
			} else if n, err := c.Writer.Write(buf); err != nil {
				return n, err
			}
		}
		n, err := c.Writer.Write(c.buf)
		c.Writer.Flush()
		return n, err
	}
	n, err := c.Writer.Write(b)
	c.Writer.Flush()
	return n, err
}

// func ServeTLS(srv *http.Server, l net.Listener) error {
// 	for {
// 		rw, e := l.Accept()
// 		if e != nil {
// 		}
// 	}
// }

// TODO: http client integration
// holy crap, getting this integrated nicely with the Go stdlib HTTP client
// stack so that it does proxying, connection pooling, and most importantly
// hostname verification is really hard. So much stuff is hardcoded to just use
// the built-in TLS lib. I think to get this to work either some crazy
// hacktackery beyond me, an almost straight up fork of the HTTP client, or
// serious stdlib internal refactoring is necessary.
// even more so, good luck getting openssl to use the operating system default
// root certificates if the user doesn't provide any. sadlol
// NOTE: if you're going to try and write your own round tripper, at least use
//  openssl.Dial, or equivalent logic

type tlsHandler struct {
	handler http.Handler
}

func (h *tlsHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
	}
	h.handler.ServeHTTP(w, req)
}

func AddRequestTLS(h http.Handler) http.Handler {
	return &tlsHandler{handler: h}
}
