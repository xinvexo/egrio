// Independent loopback-only SS2022 peer for the ignored Rust interop gate.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type echoHandler struct{}

func (echoHandler) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err := io.Copy(conn, conn)
	return err
}

func (echoHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		packet := buf.NewPacket()
		packet.Resize(1024, 0)
		destination, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return err
		}
		if err = conn.WritePacket(packet, destination); err != nil {
			return err
		}
	}
}

func (echoHandler) NewError(_ context.Context, err error) { log.Print(err) }

func serve(method, key string) error {
	service, err := shadowaead_2022.NewServiceWithPassword(method, key, 120, echoHandler{}, nil)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		return err
	}
	defer udp.Close()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if err := service.NewConnection(context.Background(), conn, M.Metadata{Source: M.SocksaddrFromNet(conn.RemoteAddr())}); err != nil {
					log.Print(err)
				}
			}()
		}
	}()
	fmt.Println(tcp.Addr())
	raw := bufio.NewPacketConn(udp)
	for {
		packet := buf.NewPacket()
		source, err := raw.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return err
		}
		if err = service.NewPacket(context.Background(), raw, packet, M.Metadata{Source: source}); err != nil {
			packet.Release()
			log.Print(err)
		}
	}
}

func client(method, key, server, target string) error {
	for _, address := range []string{server, target} {
		host, _, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return fmt.Errorf("loopback address required")
		}
	}
	methodImpl, err := shadowaead_2022.NewWithPassword(method, key, nil)
	if err != nil {
		return err
	}
	transport, err := net.DialTimeout("tcp4", server, 5*time.Second)
	if err != nil {
		return err
	}
	defer transport.Close()
	transport.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := methodImpl.DialConn(transport, M.ParseSocksaddr(target))
	if err != nil {
		return err
	}
	payload := []byte("independent-ss2022-peer")
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, reply); err != nil {
		return err
	}
	if !bytes.Equal(reply, payload) {
		return fmt.Errorf("TCP echo mismatch")
	}
	udp, err := net.DialTimeout("udp4", server, 5*time.Second)
	if err != nil {
		return err
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(5 * time.Second))
	packetConn := methodImpl.DialPacketConn(udp)
	if _, err = packetConn.WriteTo(payload, M.ParseSocksaddr(target).UDPAddr()); err != nil {
		return err
	}
	reply = make([]byte, 65536)
	n, _, err := packetConn.ReadFrom(reply)
	if err != nil {
		return err
	}
	if !bytes.Equal(reply[:n], payload) {
		return fmt.Errorf("UDP echo mismatch")
	}
	fmt.Println("TCP+UDP OK")
	return nil
}

func main() {
	var err error
	if len(os.Args) == 4 && os.Args[1] == "serve" {
		err = serve(os.Args[2], os.Args[3])
	} else if len(os.Args) == 6 && os.Args[1] == "client" {
		err = client(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	} else {
		err = fmt.Errorf("usage: ss2022-peer serve METHOD KEY | client METHOD KEY SERVER TARGET")
	}
	if err != nil {
		log.Fatal(err)
	}
}
