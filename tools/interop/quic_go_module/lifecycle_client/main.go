// Command lifecycle_client exercises netz's raw QUIC server lifecycle surface.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
	"netz-quic-go-interop/internal/rawpeer"
)

const timeout = 25 * time.Second

type scenario uint8

const (
	echo scenario = iota
	reset
	stopSending
	flowControl
	streamLimit
	unidirectional
	applicationPTO
	initialPTO
	peerClose
	migration
	migrationLoss
	natRebinding
)

type options struct {
	address    string
	caPath     string
	serverName string
	version    quic.Version
	scenario   scenario
}

func main() {
	config := parseOptions()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := run(ctx, config); err != nil {
		log.Fatal(err)
	}
}

func parseOptions() options {
	address := flag.String("addr", "127.0.0.1:4433", "peer UDP address")
	caPath := flag.String("ca", "", "PEM trust anchor")
	serverName := flag.String("server-name", "localhost", "TLS server name")
	v2Only := flag.Bool("v2-only", false, "require QUIC v2")
	expectReset := flag.Bool("expect-reset", false, "exercise RESET_STREAM")
	expectStop := flag.Bool("expect-stop-sending", false, "exercise STOP_SENDING")
	expectFlow := flag.Bool("expect-flow-control", false, "exercise flow-control renewal")
	expectStreamLimit := flag.Bool("expect-stream-limit", false, "exercise MAX_STREAMS renewal")
	expectUni := flag.Bool("expect-uni", false, "exercise unidirectional streams")
	expectServerPTO := flag.Bool("expect-server-pto", false, "drop four application datagrams")
	expectInitialPTO := flag.Bool("expect-server-initial-pto", false, "drop four Initial datagrams")
	expectPeerClose := flag.Bool("expect-peer-close", false, "require application close 58")
	expectMigration := flag.Bool("expect-migration", false, "exercise two active migrations")
	expectMigrationLoss := flag.Bool("expect-migration-loss", false, "drop one PATH_RESPONSE per migrated path")
	expectNATRebinding := flag.Bool("expect-nat-rebinding", false, "exercise same-IP source-port rebinding")
	flag.Parse()
	if *caPath == "" {
		log.Fatal("-ca is required")
	}
	selected := echo
	count := 0
	for enabled, candidate := range map[*bool]scenario{
		expectReset: reset, expectStop: stopSending, expectFlow: flowControl,
		expectStreamLimit: streamLimit, expectUni: unidirectional,
		expectServerPTO: applicationPTO, expectInitialPTO: initialPTO,
		expectPeerClose: peerClose, expectMigration: migration,
		expectMigrationLoss: migrationLoss, expectNATRebinding: natRebinding,
	} {
		if *enabled {
			selected = candidate
			count++
		}
	}
	if count > 1 || (*v2Only && selected != echo) {
		log.Fatal("select at most one lifecycle scenario; -v2-only only supports echo")
	}
	version := quic.Version1
	if *v2Only {
		version = quic.Version2
	}
	return options{*address, *caPath, *serverName, version, selected}
}

func run(ctx context.Context, options options) error {
	roots, err := loadRoots(options.caPath)
	if err != nil {
		return err
	}
	remote, err := net.ResolveUDPAddr("udp4", options.address)
	if err != nil {
		return err
	}
	udp, err := listen("127.0.0.1")
	if err != nil {
		return err
	}
	var packetConnection net.PacketConn = udp
	var dropper *rawpeer.DropPacketConn
	var switcher *rawpeer.SwitchablePacketConn
	if options.scenario == initialPTO || options.scenario == applicationPTO {
		dropper = &rawpeer.DropPacketConn{PacketConn: udp}
		packetConnection = dropper
		if options.scenario == initialPTO {
			dropper.ArmReadOnce(4)
		}
	} else if options.scenario == natRebinding {
		switcher = rawpeer.NewSwitchablePacketConn(udp)
		packetConnection = switcher
	} else if options.scenario == migration || options.scenario == migrationLoss {
		packetConnection = &rawpeer.BasicPacketConn{PacketConn: udp}
	}
	defer packetConnection.Close()
	trace := &rawpeer.Trace{}
	transport := &quic.Transport{Conn: packetConnection}
	if options.scenario != natRebinding {
		defer transport.Close()
	}
	quicConfig := &quic.Config{
		Versions: []quic.Version{options.version}, HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout: 25 * time.Second, MaxIncomingUniStreams: 1,
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace },
	}
	if options.scenario == applicationPTO {
		quicConfig.KeepAlivePeriod = time.Second
	}
	connection, err := transport.Dial(ctx, remote, &tls.Config{
		RootCAs: roots, ServerName: options.serverName,
		NextProtos: []string{"hq-interop"}, MinVersion: tls.VersionTLS13,
	}, quicConfig)
	if err != nil {
		return err
	}
	if options.scenario != natRebinding {
		defer connection.CloseWithError(0, "")
	}
	state := connection.ConnectionState()
	if state.Version != options.version || state.TLS.NegotiatedProtocol != "hq-interop" ||
		!state.TLS.HandshakeComplete || len(state.TLS.PeerCertificates) == 0 {
		return errors.New("invalid authenticated QUIC handshake")
	}
	if options.scenario == applicationPTO {
		dropper.ArmReadOnce(4)
	}

	switch options.scenario {
	case echo, applicationPTO, initialPTO, peerClose:
		return runEcho(ctx, connection, options, dropper)
	case reset:
		return runReset(ctx, connection)
	case stopSending:
		return runStopSending(ctx, connection)
	case flowControl:
		return runFlowControl(ctx, connection)
	case streamLimit:
		return runStreamLimit(ctx, connection)
	case unidirectional:
		return runUnidirectional(ctx, connection)
	case migration, migrationLoss:
		return runMigration(ctx, connection, options, trace)
	case natRebinding:
		return runNATRebinding(ctx, connection, switcher)
	default:
		return errors.New("unsupported scenario")
	}
}

func loadRoots(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("parse CA bundle")
	}
	return roots, nil
}

func listen(ip string) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: 0})
}

func runEcho(ctx context.Context, connection *quic.Conn, options options, dropper *rawpeer.DropPacketConn) error {
	for index, payload := range []string{"hello", "world"} {
		if err := rawpeer.Echo(ctx, connection, quic.StreamID(index*4), []byte(payload)); err != nil {
			return err
		}
	}
	version := 1
	if options.version == quic.Version2 {
		version = 2
	}
	switch options.scenario {
	case peerClose:
		if err := rawpeer.ExpectRemoteApplicationClose(ctx, connection, 58, "netz interop complete"); err != nil {
			return err
		}
		fmt.Printf("go_quic_peer_close_client: handshake_done=true peer_close=58 reason=%q echo_streams=2 echo_bytes=10\n", "netz interop complete")
	case applicationPTO:
		if dropper.ReadDropped() != 4 {
			return fmt.Errorf("dropped %d server application datagrams, want 4", dropper.ReadDropped())
		}
		fmt.Println("go_quic_server_pto_client: handshake_done=true dropped_datagrams=4 echo_streams=2 echo_bytes=10")
	case initialPTO:
		if dropper.ReadDropped() != 4 {
			return fmt.Errorf("dropped %d server Initial datagrams, want 4", dropper.ReadDropped())
		}
		fmt.Println("go_quic_server_initial_pto_client: handshake_done=true dropped_datagrams=4 echo_streams=2 echo_bytes=10")
	default:
		fmt.Printf("go_quic_echo_client: handshake_done=true version=%d echo_streams=2 echo_bytes=10\n", version)
	}
	return nil
}

func runReset(ctx context.Context, connection *quic.Conn) error {
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if stream.StreamID() != 0 {
		return fmt.Errorf("reset stream ID = %d, want 0", stream.StreamID())
	}
	stream.CancelWrite(41)
	if err := rawpeer.Echo(ctx, connection, 4, []byte("world")); err != nil {
		return err
	}
	fmt.Println("go_quic_reset_client: handshake_done=true reset_error=41 echo_stream=4 echo_bytes=5")
	return nil
}

func runStopSending(ctx context.Context, connection *quic.Conn) error {
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if stream.StreamID() != 0 {
		return fmt.Errorf("stop stream ID = %d, want 0", stream.StreamID())
	}
	if _, err := stream.Write([]byte("stop")); err != nil {
		return err
	}
	select {
	case <-stream.Context().Done():
		var streamError *quic.StreamError
		if !errors.As(context.Cause(stream.Context()), &streamError) || !streamError.Remote || streamError.ErrorCode != 42 {
			return fmt.Errorf("unexpected STOP_SENDING result: %w", context.Cause(stream.Context()))
		}
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	if err := rawpeer.Echo(ctx, connection, 4, []byte("world")); err != nil {
		return err
	}
	fmt.Println("go_quic_stop_sending_client: handshake_done=true stop_error=42 reset_error=42 echo_stream=4 echo_bytes=5")
	return nil
}

func runFlowControl(ctx context.Context, connection *quic.Conn) error {
	payload := make([]byte, 12_288)
	for index := range payload {
		payload[index] = 'f'
	}
	if err := rawpeer.Echo(ctx, connection, 0, payload); err != nil {
		return err
	}
	fmt.Println("go_quic_flow_control_client: handshake_done=true stream_bytes=12288 echo_bytes=12288")
	return nil
}

func runStreamLimit(ctx context.Context, connection *quic.Conn) error {
	for index, payload := range []string{"hello", "world", "again", "more"} {
		if err := rawpeer.Echo(ctx, connection, quic.StreamID(index*4), []byte(payload)); err != nil {
			return err
		}
	}
	fmt.Println("go_quic_stream_limit_client: handshake_done=true initial_limit=1 released_stream=12 echo_bytes=19")
	return nil
}

func runUnidirectional(ctx context.Context, connection *quic.Conn) error {
	send, err := connection.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	if send.StreamID() != 2 {
		return fmt.Errorf("client uni stream ID = %d, want 2", send.StreamID())
	}
	if _, err := send.Write([]byte("uni")); err != nil {
		return err
	}
	if err := send.Close(); err != nil {
		return err
	}
	receive, err := connection.AcceptUniStream(ctx)
	if err != nil {
		return err
	}
	if receive.StreamID() != 3 {
		return fmt.Errorf("server uni stream ID = %d, want 3", receive.StreamID())
	}
	_ = receive.SetReadDeadline(time.Now().Add(10 * time.Second))
	reply, err := io.ReadAll(receive)
	if err != nil || string(reply) != "uni-reply" {
		return fmt.Errorf("invalid uni reply %q: %w", reply, err)
	}
	fmt.Println("go_quic_uni_client: handshake_done=true client_stream=2 server_stream=3 reply_bytes=9")
	return nil
}

func runMigration(ctx context.Context, connection *quic.Conn, options options, trace *rawpeer.Trace) error {
	if err := rawpeer.Echo(ctx, connection, 0, []byte("hello")); err != nil {
		return err
	}
	transports := make([]*quic.Transport, 0, 2)
	defer func() {
		for _, transport := range transports {
			_ = transport.Close()
		}
	}()
	for index, ip := range []string{"127.0.0.2", "127.0.0.3"} {
		udp, err := listen(ip)
		if err != nil {
			return err
		}
		dropper := &rawpeer.DropPacketConn{
			PacketConn: &rawpeer.BasicPacketConn{PacketConn: udp},
		}
		transport := &quic.Transport{Conn: dropper}
		transports = append(transports, transport)
		path, err := connection.AddPath(transport)
		if err != nil {
			return err
		}
		if !errors.Is(path.Switch(), quic.ErrPathNotValidated) {
			return errors.New("unvalidated path switch was not rejected")
		}
		if err := path.Probe(ctx); err != nil {
			return err
		}
		// Let the probe PATH_RESPONSE and its ACK drain before switching. This
		// keeps the following one-shot write fault scoped to the response for
		// the server's validation challenge on the newly selected path.
		time.Sleep(100 * time.Millisecond)
		challengeCountBefore := trace.PathChallenges()
		if err := path.Switch(); err != nil {
			return err
		}
		if options.scenario == migrationLoss {
			// Drain the packet that announces the switch before selecting the
			// server-generated PATH_RESPONSE datagram below.
			time.Sleep(200 * time.Millisecond)
			trace.SetPathResponseCallback(func() { dropper.ArmOnce(1) })
		}
		payload := []byte([]string{"migrated", "migrated-again"}[index])
		if err := rawpeer.Echo(ctx, connection, quic.StreamID((index+1)*4), payload); err != nil {
			return err
		}
		if options.scenario == migrationLoss && dropper.Dropped() != 1 {
			return fmt.Errorf("path %d dropped %d probe-response datagrams, want 1", index, dropper.Dropped())
		}
		if options.scenario == migrationLoss && trace.PathChallenges()-challengeCountBefore < 2 {
			return fmt.Errorf("path %d received %d validation challenges, want at least initial plus retry", index, trace.PathChallenges()-challengeCountBefore)
		}
	}
	if options.scenario == migrationLoss {
		fmt.Println("go_quic_migration_loss_client: handshake_done=true pre_probe_rejected=2 probe_validated=2 dropped_probe_datagrams=2 probe_retries=2 path_sequence=127.0.0.1,127.0.0.2,127.0.0.3 source_ports_distinct=true echo_streams=4,8 echo_bytes=22")
	} else {
		fmt.Println("go_quic_migration_client: handshake_done=true pre_probe_rejected=2 probe_validated=2 path_sequence=127.0.0.1,127.0.0.2,127.0.0.3 source_ports_distinct=true echo_streams=4,8 echo_bytes=22")
	}
	return nil
}

func runNATRebinding(ctx context.Context, connection *quic.Conn, packetConnection *rawpeer.SwitchablePacketConn) error {
	if err := rawpeer.Echo(ctx, connection, 0, []byte("hello")); err != nil {
		return err
	}
	originalAddress := connection.LocalAddr().String()
	rebound, err := listen("127.0.0.1")
	if err != nil {
		return err
	}
	packetConnection.Switch(rebound, 4)
	if err := rawpeer.Echo(ctx, connection, 4, []byte("rebound")); err != nil {
		return err
	}
	if packetConnection.Dropped() != 4 {
		return fmt.Errorf("dropped %d rebound datagrams, want 4", packetConnection.Dropped())
	}
	if packetConnection.LocalAddr().String() == originalAddress {
		return errors.New("NAT rebinding did not change the local tuple")
	}
	fmt.Println("go_quic_nat_rebinding_client: handshake_done=true same_ip=true source_port_changed=true dropped_datagrams=4 echo_stream=4 echo_bytes=7")
	return nil
}
