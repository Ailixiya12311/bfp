// Package session owns BFP flows independently of their UDP or TCP carrier.
package session

import (
	"bfp/classification"
	"bfp/internal/addressscope"
	"bfp/internal/backend"
	"bfp/security"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/curve25519"
)

type Backend = backend.Dialer

// SessionBackendFactory is optional. A server creates a scope only for a newly
// confirmed Session; carrier recovery and duplicate confirmation reuse it.
type SessionBackendFactory = backend.SessionFactory

// SessionAddressAllocator is the optional logical-address view exposed by a
// server-side Session backend. It is intentionally limited to allocation and
// reverse lookup; the protocol still does not configure TUN, routes, DNS
// servers, ARP/NDP, or NAT. The allocator becomes unusable when its Session
// scope is retired.
type SessionAddressAllocator = backend.SessionAddressAllocator

// ClientAddressAllocator is a Session-owned local mapping view. It exposes no
// dial operation; target restoration and OPEN use that same Session internally.
type ClientAddressAllocator = addressscope.Allocator
type ClientAddressLeaseAllocator = addressscope.LeaseAllocator
type ClientAddressFamilyLeaseAllocator = addressscope.FamilyLeaseAllocator
type LocalAddressFamily = addressscope.AddressFamily

const (
	LocalAddressIPv4 = addressscope.IPv4
	LocalAddressIPv6 = addressscope.IPv6
)

type ClientAddressScope = addressscope.Scope
type ClientAddressScopeFactory = addressscope.Factory

type Credentials struct {
	Admission      []byte   `json:"admission"`
	Private        []byte   `json:"private"`
	Public         []byte   `json:"public"`
	ServerPublic   []byte   `json:"server_public,omitempty"`
	AllowedClients [][]byte `json:"allowed_clients,omitempty"`
}
type Options struct {
	// CloseTimeout bounds authenticated close control, independently of path
	// failure detection and retained recovery. Business resources end first.
	CloseTimeout     time.Duration
	HandshakeTimeout time.Duration
	ProbeInterval    time.Duration
	FailureTimeout   time.Duration
	UDPFailureBudget time.Duration
	RetainTimeout    time.Duration
	MaxFlows         int
	MaxFlowBuffer    int
	// MaxDatagramFlowBuffer bounds whole-message TX reservations (payload,
	// parity and conservative queue/lifecycle metadata), independently of the
	// reliable byte-stream buffer. MaxSessionBuffer remains an additional cap.
	MaxDatagramFlowBuffer int
	MaxSessionBuffer      int
	KeyUpdateBytes        uint64
	KeyUpdateInterval     time.Duration
	KeyDrainTimeout       time.Duration
	TicketTTL             time.Duration
	TicketRefreshLead     time.Duration
	TicketOverlap         time.Duration
	MaxSessionLifetime    time.Duration
}

func (o Options) defaults() Options {
	if o.CloseTimeout <= 0 {
		o.CloseTimeout = 3 * time.Second
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 3 * time.Second
	}
	if o.ProbeInterval <= 0 {
		o.ProbeInterval = time.Second
	}
	if o.FailureTimeout <= 0 {
		o.FailureTimeout = 3 * time.Second
	}
	if o.UDPFailureBudget <= 0 {
		o.UDPFailureBudget = 15 * time.Second
	}
	if o.RetainTimeout <= 0 {
		o.RetainTimeout = 30 * time.Second
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = 32
	}
	if o.MaxFlowBuffer <= 0 {
		o.MaxFlowBuffer = 128 << 10
	}
	if o.MaxDatagramFlowBuffer <= 0 {
		o.MaxDatagramFlowBuffer = 128 << 10
	}
	if o.MaxSessionBuffer <= 0 {
		o.MaxSessionBuffer = 2 << 20
	}
	if o.KeyUpdateBytes == 0 {
		o.KeyUpdateBytes = 512 << 20
	}
	if o.KeyUpdateInterval <= 0 {
		o.KeyUpdateInterval = 30 * time.Minute
	}
	if o.KeyDrainTimeout <= 0 {
		o.KeyDrainTimeout = 10 * time.Second
	}
	if o.TicketTTL == 0 {
		o.TicketTTL = 20 * time.Minute
	}
	if o.TicketRefreshLead == 0 {
		o.TicketRefreshLead = o.TicketTTL / 4
	}
	if o.TicketOverlap == 0 {
		o.TicketOverlap = min(30*time.Second, o.TicketTTL/4)
	}
	if o.MaxSessionLifetime == 0 {
		o.MaxSessionLifetime = 24 * time.Hour
	}
	return o
}

type ServerConfig struct {
	Listen      string
	Credentials Credentials
	Options     Options
	Backend     Backend
	MaxSessions int
	// nil selects classification.DefaultConfig; a non-nil config is explicit.
	Classification *classification.Config
	Negotiation    *NegotiationConfig
}
type ClientConfig struct {
	Server    string
	TCPServer string
	// Physical carrier hooks allow host applications to apply their own socket
	// routing, interface binding and upstream dialer. nil preserves net.Dialer.
	// These sockets carry BFP to the configured server, never individual flows.
	DialTCP        TCPPhysicalDialFunc
	DialUDP        UDPPhysicalDialFunc
	Credentials    Credentials
	Options        Options
	Classification *classification.Config
	Negotiation    *NegotiationConfig
	// nil keeps all automatic Datagram repair disabled. An enabled class
	// requires Datagram XOR v1 in Negotiation.OfferedCapabilities.
	DatagramFEC *DatagramFECPolicyConfig
	// nil preserves existing behavior. A factory creates an empty local map
	// only on a fresh confirmed Session, never when replacing its carrier.
	// Creation is bounded by HandshakeTimeout and an earlier Connect deadline.
	// Successful scope lifetime is owned by Session, not that creation budget.
	AddressScopeFactory ClientAddressScopeFactory
	carrierDials        *carrierDialState
	addressCreations    *clientAddressCreationState
}

func validateCredentials(c Credentials, client bool) error {
	if len(c.Admission) != 32 || len(c.Private) != 32 || len(c.Public) != 32 {
		return errors.New("session: invalid credentials")
	}
	pub, e := curve25519.X25519(c.Private, curve25519.Basepoint)
	if e != nil || subtle.ConstantTimeCompare(pub, c.Public) != 1 {
		return errors.New("session: inconsistent static keypair")
	}
	if client && len(c.ServerPublic) != 32 {
		return errors.New("session: missing pinned server key")
	}
	if client {
		if _, e := curve25519.X25519(c.Private, c.ServerPublic); e != nil {
			return errors.New("session: invalid pinned server key")
		}
	} else {
		if len(c.AllowedClients) == 0 || len(c.AllowedClients) > 4096 {
			return errors.New("session: invalid authorized device list")
		}
		seen := make(map[string]bool, len(c.AllowedClients))
		for _, allowed := range c.AllowedClients {
			if len(allowed) != 32 || seen[string(allowed)] {
				return errors.New("session: invalid authorized device key")
			}
			if _, e := curve25519.X25519(c.Private, allowed); e != nil {
				return errors.New("session: invalid authorized device key")
			}
			seen[string(allowed)] = true
		}
	}
	return nil
}
func copyCredentials(c Credentials) Credentials {
	c.Admission = append([]byte(nil), c.Admission...)
	c.Private = append([]byte(nil), c.Private...)
	c.Public = append([]byte(nil), c.Public...)
	c.ServerPublic = append([]byte(nil), c.ServerPublic...)
	allowed := make([][]byte, len(c.AllowedClients))
	for i, key := range c.AllowedClients {
		allowed[i] = append([]byte(nil), key...)
	}
	c.AllowedClients = allowed
	return c
}
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return b
}
func randomID() string { return hex.EncodeToString(randomBytes(16)) }
func keyPair(c Credentials) security.KeyPair {
	return security.KeyPair{Private: c.Private, Public: c.Public}
}

var ErrClosed = errors.New("session: closed")
var ErrCloseUnconfirmed = errors.New("session: local closed; peer close unconfirmed")
var ErrLimit = errors.New("session: resource limit")
var ErrState = errors.New("session: inconsistent recovery state")

type Stats struct {
	ID                   string `json:"session_id"`
	ClientAddress        string `json:"client_address"`
	ServerAddress        string `json:"server_address"`
	Carrier              string `json:"carrier"`
	Generation           uint64 `json:"generation"`
	Flows                int    `json:"flows"`
	Opened               uint64 `json:"opened"`
	Switches             uint64 `json:"switches"`
	WireSent             uint64 `json:"wire_sent"`
	WireReceived         uint64 `json:"wire_received"`
	Retransmissions      uint64 `json:"retransmissions"`
	Dropped              uint64 `json:"dropped"`
	TXBuffered           int    `json:"tx_buffered"`
	RXBuffered           int    `json:"rx_buffered"`
	TicketRefreshes      uint64 `json:"ticket_refreshes"`
	UDPACKSent           uint64 `json:"udp_ack_sent"`
	UDPACKReceived       uint64 `json:"udp_ack_received"`
	UDPACKCoalesced      uint64 `json:"udp_ack_coalesced"`
	UDPProbeSent         uint64 `json:"udp_probe_sent"`
	UDPPTODue            uint64 `json:"udp_pto_due"`
	UDPTransportProgress uint64 `json:"udp_transport_progress"`
	UDPStalled           uint64 `json:"udp_stalled"`
	// Session-lifetime UDP totals count only complete encrypted record writes
	// whose publications and packet-ledger commit succeeded. Wire bytes include
	// the inner record header, AEAD and padding, excluding IP/UDP headers. Feedback
	// means PacketAck sent through its separate reserve; all other records are
	// non-feedback, including controls and probes. Counters saturate.
	UDPCommittedRecords        uint64 `json:"udp_committed_records"`
	UDPCommittedWireBytes      uint64 `json:"udp_committed_wire_bytes"`
	UDPNonFeedbackRecords      uint64 `json:"udp_non_feedback_records"`
	UDPNonFeedbackWireBytes    uint64 `json:"udp_non_feedback_wire_bytes"`
	UDPFeedbackRecords         uint64 `json:"udp_feedback_records"`
	UDPFeedbackWireBytes       uint64 `json:"udp_feedback_wire_bytes"`
	UDPMaxCommittedRecordBytes uint64 `json:"udp_max_committed_record_bytes"`
	// Exact admission observations concern an encoded ordinary record. Flush
	// observations concern its existing 1200-byte/full-cwnd preselection gate,
	// and count only when scheduler or logical-retry work is pending. They are
	// not packet-loss counts; one observation can deny both reasons. Class-only
	// controls are measured by exact admission, not this preselection counter.
	UDPCwndAdmissionDenied  uint64 `json:"udp_cwnd_admission_denied"`
	UDPPacerAdmissionDenied uint64 `json:"udp_pacer_admission_denied"`
	UDPFlushCwndGateDenied  uint64 `json:"udp_flush_cwnd_gate_denied"`
	UDPFlushPacerGateDenied uint64 `json:"udp_flush_pacer_gate_denied"`
	// The blocked clock spans the first observed ordinary-budget denial until
	// a successful non-feedback send, an observed empty scheduler/retry set,
	// suspension, close or rebind. It is an observation episode, not a per-packet
	// or end-to-end wait. Cwnd/pacer overlap and reason changes share one interval.
	// Read-only snapshots include the ongoing interval without closing it.
	UDPBudgetBlockedMS    uint64 `json:"udp_budget_blocked_ms"`
	UDPBudgetBlockedMaxMS uint64 `json:"udp_budget_blocked_max_ms"`
	UDPBudgetBlocked      bool   `json:"udp_budget_blocked"`
	UDPBlockedByCwnd      bool   `json:"udp_blocked_by_cwnd"`
	UDPBlockedByPacer     bool   `json:"udp_blocked_by_pacer"`
	// Path gauges belong to the current UDP carrier, including its suspended
	// state until attachment resets it. Milliseconds are nonnegative snapshots.
	UDPPathPresent         bool    `json:"udp_path_present"`
	UDPSuspect             bool    `json:"udp_suspect"`
	UDPNoResponseDeadlines uint8   `json:"udp_no_response_deadlines"`
	UDPPTORounds           uint8   `json:"udp_pto_rounds"`
	UDPBasePTOMS           uint64  `json:"udp_base_pto_ms"`
	UDPDeadlineRemainingMS uint64  `json:"udp_deadline_remaining_ms"`
	UDPNoProgressAgeMS     uint64  `json:"udp_no_progress_age_ms"`
	UDPPathGeneration      uint64  `json:"udp_path_generation"`
	UDPPathActive          bool    `json:"udp_path_active"`
	UDPCwndBytes           uint64  `json:"udp_cwnd_bytes"`
	UDPFlightBytes         uint64  `json:"udp_flight_bytes"`
	UDPPacerTokens         float64 `json:"udp_pacer_tokens"`
	UDPFeedbackTokens      float64 `json:"udp_feedback_tokens"`
	UDPLastCommittedBytes  uint64  `json:"udp_last_committed_bytes"`
	// Copy the existing estimator without introducing sampling. Latest/Min are
	// its raw eligible samples; Smoothed may subtract bounded ACK delay. Samples
	// zero means Smoothed/Variance are estimator defaults, not measured RTTs.
	UDPRTTSmoothedUS uint64 `json:"udp_rtt_smoothed_us"`
	UDPRTTVarianceUS uint64 `json:"udp_rtt_variance_us"`
	UDPRTTMinUS      uint64 `json:"udp_rtt_min_us"`
	UDPRTTLatestUS   uint64 `json:"udp_rtt_latest_us"`
	UDPRTTSamples    uint64 `json:"udp_rtt_samples"`
	// These saturating counters cover physical TCP recovery candidates. A
	// failure includes cancellation or rejection before attachment/merge;
	// no raw error, candidate token, or credentials are retained here.
	TCPRecoveryAttempts uint64 `json:"tcp_recovery_attempts"`
	TCPRecoveryFailures uint64 `json:"tcp_recovery_failures"`
	TCPRecoveryInFlight bool   `json:"tcp_recovery_in_flight"`
	// Repair counters exclude original application bytes and do not imply a
	// reliable Datagram contract. Sent counts only complete record commits.
	FECRepairSent         uint64 `json:"fec_repair_sent"`
	FECRepairReceived     uint64 `json:"fec_repair_received"`
	FECRecoveredDatagrams uint64 `json:"fec_recovered_datagrams"`
	FECRejected           uint64 `json:"fec_rejected"`
}
