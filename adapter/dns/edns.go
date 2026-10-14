package dns

import "golang.org/x/net/dns/dnsmessage"

const (
	defaultUDPPayload                  = 512
	rCodeBadVersion   dnsmessage.RCode = 16
)

type ednsParameters struct {
	enabled  bool
	payload  int
	dnssecOK bool
}

// Accept one root OPT. Unsupported option codes (including padding, cookies
// and client subnet) are ignored rather than echoed or used as target metadata.
// The maintained DNS parser has already validated their wire representation.
func parseEDNS(query dnsmessage.Message) (ednsParameters, dnsmessage.RCode) {
	parameters := ednsParameters{payload: defaultUDPPayload}
	if len(query.Additionals) == 0 {
		return parameters, dnsmessage.RCodeSuccess
	}
	if len(query.Additionals) != 1 {
		return parameters, dnsmessage.RCodeFormatError
	}
	opt := query.Additionals[0]
	if _, ok := opt.Body.(*dnsmessage.OPTResource); !ok || opt.Header.Type != dnsmessage.TypeOPT || opt.Header.Name.String() != "." {
		return parameters, dnsmessage.RCodeFormatError
	}
	parameters.enabled = true
	parameters.payload = min(max(int(opt.Header.Class), defaultUDPPayload), maxMessageBytes)
	parameters.dnssecOK = opt.Header.TTL&0x8000 != 0
	// A query cannot already carry an extended error code.
	if opt.Header.TTL>>24 != 0 {
		return parameters, dnsmessage.RCodeFormatError
	}
	if (opt.Header.TTL>>16)&0xff != 0 {
		return parameters, rCodeBadVersion
	}
	return parameters, dnsmessage.RCodeSuccess
}

func (p ednsParameters) attach(reply *preparedReply, code dnsmessage.RCode) *preparedReply {
	reply.udpLimit = p.payload
	if p.enabled {
		var header dnsmessage.ResourceHeader
		_ = header.SetEDNS0(maxMessageBytes, code, p.dnssecOK)
		reply.message.RCode = code & 0xf
		reply.message.Additionals = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.OPTResource{}}}
	}
	return reply
}

func (p ednsParameters) queryError(query dnsmessage.Message, code dnsmessage.RCode) *preparedReply {
	return p.attach(dnsQueryError(query, code&0xf), code)
}
