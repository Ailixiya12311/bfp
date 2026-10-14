package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/sing/common"
)

type packetSender struct {
	ctx    context.Context
	cancel context.CancelFunc
	ch     chan C.PacketAdapter

	// destination NAT mapping
	originToTarget map[string]netip.Addr
	targetToOrigin map[netip.Addr]netip.Addr
	mappingMutex   sync.RWMutex
}

// newPacketSender return a chan based C.PacketSender
// It ensures that packets can be sent sequentially and without blocking
func newPacketSender() C.PacketSender {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan C.PacketAdapter, senderCapacity)
	return &packetSender{
		ctx:    ctx,
		cancel: cancel,
		ch:     ch,

		originToTarget: make(map[string]netip.Addr),
		targetToOrigin: make(map[netip.Addr]netip.Addr),
	}
}

func (s *packetSender) AddMapping(originMetadata *C.Metadata, metadata *C.Metadata) {
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	originKey := originMetadata.String()
	originAddr := originMetadata.DstIP
	targetAddr := metadata.DstIP
	if addr := s.originToTarget[originKey]; !addr.IsValid() { // overwrite only if the record is illegal
		s.originToTarget[originKey] = targetAddr
	}
	if addr := s.targetToOrigin[targetAddr]; !addr.IsValid() { // overwrite only if the record is illegal
		s.targetToOrigin[targetAddr] = originAddr
	}
}

func (s *packetSender) RestoreReadFrom(addr netip.Addr) netip.Addr {
	s.mappingMutex.RLock()
	defer s.mappingMutex.RUnlock()
	if originAddr := s.targetToOrigin[addr]; originAddr.IsValid() {
		return originAddr
	}
	return addr
}

func (s *packetSender) processPacket(pc C.PacketConn, packet C.PacketAdapter) {
	defer packet.Drop()
	metadata := packet.Metadata()
	if logical, ok := common.Cast[C.LogicalUDPPacketConn](pc); ok {
		// Preserve the actual inbound destination before fake-IP restoration
		// clears it. Logical outbounds keep this per target, rather than the
		// IP-only sender map whose aliases can collide across domains.
		origin := metadata.AddrPort()
		metadata = metadata.Clone()
		if err := preHandleMetadata(metadata); err != nil {
			log.Warnln("[UDP] Logical destination error: %s", err)
			return
		}
		addr, err := logical.PrepareUDPMetadata(s.ctx, metadata, origin)
		if err != nil || addr == nil {
			log.Warnln("[UDP] Logical destination preparation failed: %s", err)
			return
		}
		// Keep the tracker and its normal WriteTo accounting in the path. A
		// logical adapter may have reserved provisional metadata in Prepare;
		// publish it only after the actual PacketConn write succeeds.
		if err := handleUDPToRemote(packet, pc, addr); err != nil {
			if transaction, ok := common.Cast[C.LogicalUDPPacketConnTransaction](pc); ok {
				transaction.AbortUDPMetadata(addr)
			}
			return
		}
		if transaction, ok := common.Cast[C.LogicalUDPPacketConnTransaction](pc); ok {
			if err := transaction.CommitUDPMetadata(addr); err != nil {
				transaction.AbortUDPMetadata(addr)
				log.Warnln("[UDP] Logical destination commit failed: %s", err)
			}
		}
		return
	}

	var addr *net.UDPAddr

	s.mappingMutex.RLock()
	targetAddr := s.originToTarget[metadata.String()]
	s.mappingMutex.RUnlock()

	if targetAddr.IsValid() {
		addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(targetAddr, metadata.DstPort))
	}

	if addr == nil {
		originMetadata := metadata  // save origin metadata
		metadata = metadata.Clone() // don't modify PacketAdapter's metadata

		_ = preHandleMetadata(metadata) // error was pre-checked
		metadata = metadata.Pure()
		if metadata.Host != "" {
			// TODO: ResolveUDP may take a long time to block the Process loop
			//       but we want keep sequence sending so can't open a new goroutine
			if err := pc.ResolveUDP(s.ctx, metadata); err != nil {
				log.Warnln("[UDP] Resolve Ip error: %s", err)
				return
			}
		}

		if !metadata.DstIP.IsValid() {
			log.Warnln("[UDP] Destination ip not valid: %#v", metadata)
			return
		}
		s.AddMapping(originMetadata, metadata)
		addr = metadata.UDPAddr()
	}
	_ = handleUDPToRemote(packet, pc, addr)
}

func (s *packetSender) Process(pc C.PacketConn, proxy C.WriteBackProxy) {
	for {
		select {
		case <-s.ctx.Done():
			return // sender closed
		case packet := <-s.ch:
			if proxy != nil {
				proxy.UpdateWriteBack(packet)
			}
			s.processPacket(pc, packet)
		}
	}
}

func (s *packetSender) dropAll() {
	for {
		select {
		case data := <-s.ch:
			data.Drop() // drop all data still in chan
		default:
			return // no data, exit goroutine
		}
	}
}

func (s *packetSender) Send(packet C.PacketAdapter) {
	select {
	case <-s.ctx.Done():
		packet.Drop() // sender closed before Send()
		return
	default:
	}

	select {
	case s.ch <- packet:
		// put ok, so don't drop packet, will process by other side of chan
	case <-s.ctx.Done():
		packet.Drop() // sender closed when putting data to chan
	default:
		packet.Drop() // chan is full
	}
}

func (s *packetSender) Close() {
	s.cancel()
	s.dropAll()
}

func (s *packetSender) DoSniff(metadata *C.Metadata) error { return nil }

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, addr net.Addr) error {
	if !isUDPAddress(addr) {
		return errors.New("udp addr invalid")
	}
	if numeric, ok := addr.(*net.UDPAddr); ok && numeric == nil {
		return errors.New("udp addr invalid")
	}

	n, err := pc.WriteTo(packet.Data(), addr)
	if err != nil {
		return err
	}
	if n != len(packet.Data()) {
		return io.ErrShortWrite
	}
	// reset timeout
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func isUDPAddress(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	value := reflect.ValueOf(addr)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return false
		}
	}
	return addr.Network() == "udp"
}

func handleUDPToLocal(writeBack C.WriteBack, pc C.PacketConn, sender C.PacketSender, key string, oAddrPort netip.AddrPort) {
	defer func() {
		sender.Close()
		_ = pc.Close()
		closeAllLocalCoon(key)
		natTable.Delete(key)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		data, put, from, err := pc.WaitReadFrom()
		if err != nil {
			if put != nil {
				put()
			}
			return
		}

		if logical, ok := common.Cast[C.LogicalUDPPacketConn](pc); ok {
			from, err = logical.RestoreUDPSource(from)
			if err != nil || !isUDPAddress(from) {
				if put != nil {
					put()
				}
				return
			}
			if numericSource, numeric := from.(*net.UDPAddr); numeric {
				if numericSource == nil || !numericSource.AddrPort().IsValid() || numericSource.Port == 0 {
					if put != nil {
						put()
					}
					return
				}
			} else {
				// A domain-capable inbound (for example SOCKS5) can encode
				// the restored source directly. Unsupported inbounds return
				// an error; never silently replace it with the first target.
				_, err = writeBack.WriteBack(data, from)
				if put != nil {
					put()
				}
				if err != nil {
					return
				}
				continue
			}
		}

		fromUDPAddr, isUDPAddr := from.(*net.UDPAddr)
		if !isUDPAddr {
			fromUDPAddr = net.UDPAddrFromAddrPort(oAddrPort) // oAddrPort was Unmapped
			log.Warnln("server return a [%T](%s) which isn't a *net.UDPAddr, force replace to (%s), this may be caused by a wrongly implemented server", from, from, oAddrPort)
		} else if fromUDPAddr == nil {
			fromUDPAddr = net.UDPAddrFromAddrPort(oAddrPort) // oAddrPort was Unmapped
			log.Warnln("server return a nil *net.UDPAddr, force replace to (%s), this may be caused by a wrongly implemented server", oAddrPort)
		}

		fromAddrPort := fromUDPAddr.AddrPort()
		fromAddr := fromAddrPort.Addr().Unmap()

		// restore DestinationNAT
		fromAddr = sender.RestoreReadFrom(fromAddr).Unmap()

		fromAddrPort = netip.AddrPortFrom(fromAddr, fromAddrPort.Port())

		_, err = writeBack.WriteBack(data, net.UDPAddrFromAddrPort(fromAddrPort))
		if put != nil {
			put()
		}
		if err != nil {
			return
		}
	}
}

func closeAllLocalCoon(lAddr string) {
	natTable.RangeForLocalConn(lAddr, func(key string, value *net.UDPConn) bool {
		conn := value

		conn.Close()
		log.Debugln("Closing TProxy local conn... lAddr=%s rAddr=%s", lAddr, key)
		return true
	})
}

func handleSocket(inbound, outbound net.Conn) {
	N.Relay(inbound, outbound)
}
