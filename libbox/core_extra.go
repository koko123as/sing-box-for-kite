package libbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/networkquality"
	"github.com/sagernet/sing-box/common/stun"
	"github.com/sagernet/sing-box/daemon"
	M "github.com/sagernet/sing/common/metadata"

	mihomoYAML "github.com/metacubex/mihomo/common/yaml"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	mihomoDNS "github.com/metacubex/mihomo/dns"
	mihomoListener "github.com/metacubex/mihomo/listener"
	mihomoListenerConfig "github.com/metacubex/mihomo/listener/config"
	mihomoInner "github.com/metacubex/mihomo/listener/inner"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
	xrayNet "github.com/xtls/xray-core/common/net"
	xraySession "github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// dialThroughCore opens a TCP connection routed by the running Xray or mihomo
// core exactly like app traffic (rules, selected node), for the dashboard's
// egress IP check.
func dialThroughCore(ctx context.Context, running *runningCore, network, address string) (net.Conn, error) {
	return dialThroughCoreTag(ctx, running, "", address)
}

// dialThroughCoreTag dials through one named outbound/proxy when tag is set,
// otherwise through the core's routing.
func dialThroughCoreTag(ctx context.Context, running *runningCore, tag, address string) (net.Conn, error) {
	switch running.core {
	case CoreXray:
		if running.xray == nil {
			return nil, fmt.Errorf("xray is not running")
		}
		destination, err := xrayNet.ParseDestination("tcp:" + address)
		if err != nil {
			return nil, err
		}
		if tag != "" {
			ctx = xraySession.SetForcedOutboundTagToContext(ctx, tag)
		}
		return xrayCore.Dial(ctx, running.xray, destination)
	case CoreMihomo:
		conn, err := mihomoInner.HandleTcp(mihomoTunnel.Tunnel, address, tag)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		return &afterFuncConn{Conn: conn, stop: stop}, nil
	default:
		return nil, fmt.Errorf("unknown core: %s", running.core)
	}
}

type afterFuncConn struct {
	net.Conn
	stop func() bool
}

func (c *afterFuncConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

// idleWhileOtherCore serves a sing-box-only status stream (Tailscale,
// OpenConnect, OpenVPN, Taildrop): while Xray or mihomo runs there is nothing
// to report, so the stream stays open and empty instead of failing with
// "invalid argument" (the sing-box service itself is idle then).
func idleWhileOtherCore[T any](server grpc.ServerStreamingServer[T], singBox func(grpc.ServerStreamingServer[T]) error) error {
	return switchStream(server, singBox, func(ctx context.Context, _ *runningCore, _ func(*T) error) error {
		<-ctx.Done()
		return ctx.Err()
	})
}

func (s *coreStartedService) SubscribeTailscaleStatus(empty *emptypb.Empty, server grpc.ServerStreamingServer[daemon.TailscaleStatusUpdate]) error {
	return idleWhileOtherCore(server, func(stream grpc.ServerStreamingServer[daemon.TailscaleStatusUpdate]) error {
		return s.StartedService.SubscribeTailscaleStatus(empty, stream)
	})
}

func (s *coreStartedService) SubscribeOpenConnectStatus(empty *emptypb.Empty, server grpc.ServerStreamingServer[daemon.OpenConnectStatusUpdate]) error {
	return idleWhileOtherCore(server, func(stream grpc.ServerStreamingServer[daemon.OpenConnectStatusUpdate]) error {
		return s.StartedService.SubscribeOpenConnectStatus(empty, stream)
	})
}

func (s *coreStartedService) SubscribeOpenVPNStatus(empty *emptypb.Empty, server grpc.ServerStreamingServer[daemon.OpenVPNStatusUpdate]) error {
	return idleWhileOtherCore(server, func(stream grpc.ServerStreamingServer[daemon.OpenVPNStatusUpdate]) error {
		return s.StartedService.SubscribeOpenVPNStatus(empty, stream)
	})
}

func (s *coreStartedService) SubscribeTaildropInbox(request *daemon.SubscribeTaildropInboxRequest, server grpc.ServerStreamingServer[daemon.TaildropInbox]) error {
	return idleWhileOtherCore(server, func(stream grpc.ServerStreamingServer[daemon.TaildropInbox]) error {
		return s.StartedService.SubscribeTaildropInbox(request, stream)
	})
}

// CoreProfileStats counts a profile's groups, outbounds and rules for the
// dashboard card, as JSON {"groups":n,"outbounds":n,"rules":n}. mihomo:
// proxy-groups / proxies (+ providers) / rules; Xray: routing.balancers /
// outbounds / routing.rules.
func CoreProfileStats(core string, content string) (string, error) {
	var groups, outbounds, rules int
	switch core {
	case CoreMihomo:
		var root struct {
			Proxies   []any          `yaml:"proxies"`
			Providers map[string]any `yaml:"proxy-providers"`
			Groups    []any          `yaml:"proxy-groups"`
			Rules     []any          `yaml:"rules"`
		}
		if err := mihomoYAML.Unmarshal([]byte(normalizeCoreContent(content)), &root); err != nil {
			return "", err
		}
		groups, outbounds, rules = len(root.Groups), len(root.Proxies)+len(root.Providers), len(root.Rules)
	case CoreXray:
		var root struct {
			Outbounds []json.RawMessage `json:"outbounds"`
			Routing   struct {
				Balancers []json.RawMessage `json:"balancers"`
				Rules     []json.RawMessage `json:"rules"`
			} `json:"routing"`
		}
		if err := json.Unmarshal([]byte(normalizeCoreContent(content)), &root); err != nil {
			return "", err
		}
		groups, outbounds, rules = len(root.Routing.Balancers), len(root.Outbounds), len(root.Routing.Rules)
	default:
		return "", fmt.Errorf("unsupported core: %s", core)
	}
	encoded, err := json.Marshal(map[string]int{"groups": groups, "outbounds": outbounds, "rules": rules})
	return string(encoded), err
}

// ---- remaining sing-box-only calls, answered for Xray/mihomo ----

var (
	coreGroupExpandAccess sync.Mutex
	coreGroupCollapsed    = map[string]bool{}
)

func coreGroupExpanded(tag string) bool {
	coreGroupExpandAccess.Lock()
	defer coreGroupExpandAccess.Unlock()
	return !coreGroupCollapsed[tag]
}

func (s *coreStartedService) SetGroupExpand(ctx context.Context, request *daemon.SetGroupExpandRequest) (*emptypb.Empty, error) {
	if otherCore() == nil {
		return s.StartedService.SetGroupExpand(ctx, request)
	}
	coreGroupExpandAccess.Lock()
	coreGroupCollapsed[request.GroupTag] = !request.IsExpand
	coreGroupExpandAccess.Unlock()
	go notifyGroupsChange()
	return &emptypb.Empty{}, nil
}

func (s *coreStartedService) GetDefaultLogLevel(ctx context.Context, empty *emptypb.Empty) (*daemon.DefaultLogLevel, error) {
	running := otherCore()
	if running == nil {
		return s.StartedService.GetDefaultLogLevel(ctx, empty)
	}
	return &daemon.DefaultLogLevel{Level: running.logLevel}, nil
}

func (s *coreStartedService) GetDeprecatedWarnings(ctx context.Context, empty *emptypb.Empty) (*daemon.DeprecatedWarnings, error) {
	if otherCore() == nil {
		return s.StartedService.GetDeprecatedWarnings(ctx, empty)
	}
	return &daemon.DeprecatedWarnings{}, nil
}

// ---- network quality / STUN through Xray or mihomo ----

// coreDialer adapts the running core to sing's N.Dialer for the diagnostics
// tools. UDP goes through Xray's dispatcher; mihomo offers no inner UDP path.
type coreDialer struct {
	running *runningCore
	tag     string
}

func (d *coreDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("%s: only TCP is available here", d.running.core)
	}
	return dialThroughCoreTag(ctx, d.running, d.tag, destination.String())
}

func (d *coreDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d.running.core != CoreXray || d.running.xray == nil {
		return nil, fmt.Errorf("UDP tests are not available with the %s core", d.running.core)
	}
	if d.tag != "" {
		ctx = xraySession.SetForcedOutboundTagToContext(ctx, d.tag)
	}
	return xrayCore.DialUDP(ctx, d.running.xray)
}

func (s *coreStartedService) StartNetworkQualityTest(request *daemon.NetworkQualityTestRequest, server grpc.ServerStreamingServer[daemon.NetworkQualityTestProgress]) error {
	running := otherCore()
	if running == nil {
		return s.StartedService.StartNetworkQualityTest(request, server)
	}
	nqDialer := &coreDialer{running: running, tag: request.OutboundTag}
	httpClient := networkquality.NewHTTPClient(nqDialer)
	defer httpClient.CloseIdleConnections()
	factory, err := networkquality.NewOptionalHTTP3Factory(nqDialer, request.Http3)
	if err != nil {
		return err
	}
	result, nqErr := networkquality.Run(networkquality.Options{
		ConfigURL:            request.ConfigURL,
		HTTPClient:           httpClient,
		NewMeasurementClient: factory,
		Serial:               request.Serial,
		MaxRuntime:           time.Duration(request.MaxRuntimeSeconds) * time.Second,
		Context:              server.Context(),
		OnProgress: func(p networkquality.Progress) {
			_ = server.Send(daemon.NewNetworkQualityTestProgress(p))
		},
	})
	if nqErr != nil {
		return server.Send(&daemon.NetworkQualityTestProgress{IsFinal: true, Error: nqErr.Error()})
	}
	return server.Send(daemon.NewNetworkQualityTestResult(result))
}

func (s *coreStartedService) StartSTUNTest(request *daemon.STUNTestRequest, server grpc.ServerStreamingServer[daemon.STUNTestProgress]) error {
	running := otherCore()
	if running == nil {
		return s.StartedService.StartSTUNTest(request, server)
	}
	result, stunErr := stun.Run(stun.Options{
		Server:  request.Server,
		Dialer:  &coreDialer{running: running, tag: request.OutboundTag},
		Context: server.Context(),
		OnProgress: func(p stun.Progress) {
			_ = server.Send(daemon.NewSTUNTestProgress(p))
		},
	})
	if stunErr != nil {
		return server.Send(&daemon.STUNTestProgress{IsFinal: true, Error: stunErr.Error()})
	}
	return server.Send(daemon.NewSTUNTestResult(result))
}

// mihomoCloseListeners releases every port the profile opened (mixed-port,
// port, socks-port, listeners:, tunnels:, dns.listen). executor.Shutdown only
// closes the TUN, which left e.g. 7890 bound and broke the next sing-box start.
func mihomoCloseListeners() {
	tunnel := mihomoTunnel.Tunnel
	mihomoListener.PatchInboundListeners(map[string]mihomoConstant.InboundListener{}, tunnel, true)
	mihomoListener.PatchTunnel(nil, tunnel)
	mihomoListener.ReCreateHTTP(0, tunnel)
	mihomoListener.ReCreateSocks(0, tunnel)
	mihomoListener.ReCreateRedir(0, tunnel)
	mihomoListener.ReCreateTProxy(0, tunnel)
	mihomoListener.ReCreateMixed(0, tunnel)
	mihomoListener.ReCreateShadowSocks("", tunnel)
	mihomoListener.ReCreateVmess("", tunnel)
	mihomoListener.ReCreateTuic(mihomoListenerConfig.TuicServer{}, tunnel)
	mihomoDNS.ReCreateServer("", nil, nil)
}

func (s *coreStartedService) SubscribeUSBIPServerStatus(empty *emptypb.Empty, server grpc.ServerStreamingServer[daemon.USBIPServerStatusUpdate]) error {
	return idleWhileOtherCore(server, func(stream grpc.ServerStreamingServer[daemon.USBIPServerStatusUpdate]) error {
		return s.StartedService.SubscribeUSBIPServerStatus(empty, stream)
	})
}

// ProvideUSBDevices waits while Xray or mihomo runs (no USB/IP server there)
// instead of failing, and hands over to sing-box once it is the running core.
func (s *coreStartedService) ProvideUSBDevices(server grpc.BidiStreamingServer[daemon.USBProviderMessage, daemon.USBServerMessage]) error {
	for otherCore() != nil {
		change, _ := currentCoreChange()
		select {
		case <-change:
		case <-server.Context().Done():
			return server.Context().Err()
		}
	}
	return s.StartedService.ProvideUSBDevices(server)
}
