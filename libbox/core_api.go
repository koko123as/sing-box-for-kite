package libbox

// Phase 3: one gRPC interface for every core. coreStartedService embeds
// daemon.StartedService (which serves sing-box) and answers the calls the UI
// and remote control use from Xray or mihomo while one of them runs. A stream
// opened under one core switches to the next when the running core changes.

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	mihomoOutboundGroup "github.com/metacubex/mihomo/adapter/outboundgroup"
	mihomoCacheFile "github.com/metacubex/mihomo/component/profile/cachefile"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
	mihomoStatistic "github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing/common/memory"
	xrayNet "github.com/xtls/xray-core/common/net"
	xraySession "github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
	xrayRouting "github.com/xtls/xray-core/features/routing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const coreURLTestURL = "https://www.gstatic.com/generate_204"

// ---- core change notification ----

var (
	coreChangeAccess sync.Mutex
	coreChange       = make(chan struct{})
	groupsChange     = make(chan struct{})
)

func notifyCoreChange() {
	coreChangeAccess.Lock()
	close(coreChange)
	coreChange = make(chan struct{})
	close(groupsChange)
	groupsChange = make(chan struct{})
	coreChangeAccess.Unlock()
}

func notifyGroupsChange() {
	coreChangeAccess.Lock()
	close(groupsChange)
	groupsChange = make(chan struct{})
	coreChangeAccess.Unlock()
}

func currentCoreChange() (<-chan struct{}, <-chan struct{}) {
	coreChangeAccess.Lock()
	defer coreChangeAccess.Unlock()
	return coreChange, groupsChange
}

func otherCore() *runningCore {
	coreAccess.Lock()
	defer coreAccess.Unlock()
	return activeCore
}

// ---- stream switching ----

type switchingStream[T any] struct {
	grpc.ServerStreamingServer[T]
	ctx context.Context
}

func (s *switchingStream[T]) Context() context.Context { return s.ctx }

func (s *switchingStream[T]) Send(message *T) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	return s.ServerStreamingServer.Send(message)
}

// switchStream serves a stream with sing-box's implementation or the other
// core's, restarting it on the right one whenever the running core changes.
func switchStream[T any](server grpc.ServerStreamingServer[T], singBox func(grpc.ServerStreamingServer[T]) error, other func(context.Context, *runningCore, func(*T) error) error) error {
	for {
		change, _ := currentCoreChange()
		ctx, cancel := context.WithCancel(server.Context())
		stream := &switchingStream[T]{ServerStreamingServer: server, ctx: ctx}
		done := make(chan error, 1)
		running := otherCore()
		go func() {
			if running == nil {
				done <- singBox(stream)
			} else {
				done <- other(ctx, running, stream.Send)
			}
		}()
		select {
		case err := <-done:
			cancel()
			return err
		case <-change:
			cancel()
			<-done
		case <-server.Context().Done():
			cancel()
			<-done
			return server.Context().Err()
		}
	}
}

type coreStartedService struct {
	*daemon.StartedService
}

func (s *coreStartedService) SubscribeServiceStatus(empty *emptypb.Empty, server grpc.ServerStreamingServer[daemon.ServiceStatus]) error {
	return switchStream(server, func(stream grpc.ServerStreamingServer[daemon.ServiceStatus]) error {
		return s.StartedService.SubscribeServiceStatus(empty, stream)
	}, func(ctx context.Context, running *runningCore, send func(*daemon.ServiceStatus) error) error {
		if err := send(&daemon.ServiceStatus{Status: daemon.ServiceStatus_STARTED}); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
}

func (s *coreStartedService) GetStartedAt(ctx context.Context, empty *emptypb.Empty) (*daemon.StartedAt, error) {
	if running := otherCore(); running != nil {
		return &daemon.StartedAt{StartedAt: running.startedAt.UnixMilli()}, nil
	}
	return s.StartedService.GetStartedAt(ctx, empty)
}

func (s *coreStartedService) SubscribeStatus(request *daemon.SubscribeStatusRequest, server grpc.ServerStreamingServer[daemon.Status]) error {
	return switchStream(server, func(stream grpc.ServerStreamingServer[daemon.Status]) error {
		return s.StartedService.SubscribeStatus(request, stream)
	}, func(ctx context.Context, running *runningCore, send func(*daemon.Status) error) error {
		interval := time.Duration(request.Interval)
		if interval <= 0 {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var lastUp, lastDown int64
		first := true
		for {
			current := &daemon.Status{Memory: memory.Total(), Goroutines: int32(runtime.NumGoroutine())}
			if running.core == CoreMihomo || running.xrayTrack != nil {
				current.TrafficAvailable = true
				if running.core == CoreMihomo {
					snapshot := mihomoStatistic.DefaultManager.Snapshot()
					current.UplinkTotal, current.DownlinkTotal = snapshot.UploadTotal, snapshot.DownloadTotal
					current.ConnectionsIn = int32(len(snapshot.Connections))
				} else {
					up, down, count := running.xrayTrack.totals()
					current.UplinkTotal, current.DownlinkTotal = up, down
					current.ConnectionsIn = int32(count)
				}
				current.ConnectionsOut = current.ConnectionsIn
				if !first {
					current.Uplink, current.Downlink = current.UplinkTotal-lastUp, current.DownlinkTotal-lastDown
				}
				lastUp, lastDown, first = current.UplinkTotal, current.DownlinkTotal, false
			}
			if err := send(current); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	})
}

// ---- groups ----

func (s *coreStartedService) SubscribeGroups(empty *emptypb.Empty, server grpc.ServerStreamingServer[daemon.Groups]) error {
	return switchStream(server, func(stream grpc.ServerStreamingServer[daemon.Groups]) error {
		return s.StartedService.SubscribeGroups(empty, stream)
	}, func(ctx context.Context, running *runningCore, send func(*daemon.Groups) error) error {
		// Delays change without a notification (mihomo health checks,
		// Xray observatory), so the list is also refreshed periodically.
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			_, groups := currentCoreChange()
			if err := send(readCoreGroups(running)); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-groups:
			case <-ticker.C:
			}
		}
	})
}

func readCoreGroups(running *runningCore) *daemon.Groups {
	switch running.core {
	case CoreMihomo:
		return readMihomoGroups()
	case CoreXray:
		return readXrayGroups(running)
	}
	return &daemon.Groups{}
}

func mihomoGroupType(proxyType mihomoConstant.AdapterType) string {
	switch proxyType {
	case mihomoConstant.Selector:
		return "selector"
	case mihomoConstant.URLTest:
		return "urltest"
	case mihomoConstant.Fallback:
		return "fallback"
	case mihomoConstant.LoadBalance:
		return "loadbalance"
	}
	return strings.ToLower(proxyType.String())
}

func mihomoGroups() []mihomoConstant.Proxy {
	proxies := mihomoTunnel.Proxies()
	var ordered []mihomoConstant.Proxy
	seen := map[string]bool{}
	// GLOBAL lists every group in profile order.
	if global, ok := proxies["GLOBAL"]; ok {
		if group, ok := global.Adapter().(mihomoOutboundGroup.ProxyGroup); ok {
			for _, proxy := range group.Proxies() {
				if _, isGroup := proxy.Adapter().(mihomoOutboundGroup.ProxyGroup); isGroup && !seen[proxy.Name()] {
					seen[proxy.Name()] = true
					ordered = append(ordered, proxy)
				}
			}
		}
	}
	var rest []string
	for name, proxy := range proxies {
		if _, isGroup := proxy.Adapter().(mihomoOutboundGroup.ProxyGroup); isGroup && !seen[name] && name != "GLOBAL" {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		ordered = append(ordered, proxies[name])
	}
	if mihomoTunnel.Mode() == mihomoTunnel.Global {
		if global, ok := proxies["GLOBAL"]; ok {
			ordered = append([]mihomoConstant.Proxy{global}, ordered...)
		}
	}
	return ordered
}

func readMihomoGroups() *daemon.Groups {
	var groups daemon.Groups
	for _, proxy := range mihomoGroups() {
		group := proxy.Adapter().(mihomoOutboundGroup.ProxyGroup)
		if group.Hidden() {
			continue
		}
		item := &daemon.Group{
			Tag:        proxy.Name(),
			Type:       mihomoGroupType(proxy.Type()),
			Selectable: proxy.Type() == mihomoConstant.Selector,
			Selected:   group.Now(),
			IsExpand:   coreGroupExpanded(proxy.Name()),
		}
		for _, member := range group.Proxies() {
			entry := &daemon.GroupItem{Tag: member.Name(), Type: strings.ToLower(member.Type().String())}
			if delay := member.LastDelayForTestUrl(coreURLTestURL); delay > 0 && delay < 0xffff {
				entry.UrlTestDelay = int32(delay)
				entry.UrlTestTime = time.Now().Unix()
			} else if history := member.DelayHistory(); len(history) > 0 {
				last := history[len(history)-1]
				if last.Delay > 0 {
					entry.UrlTestDelay = int32(last.Delay)
					entry.UrlTestTime = last.Time.Unix()
				}
			}
			item.Items = append(item.Items, entry)
		}
		if len(item.Items) > 0 {
			groups.Group = append(groups.Group, item)
		}
	}
	return &groups
}

// Xray has no selector; each routing balancer is shown as a group whose
// "auto" entry follows the balancer strategy and whose other entries pin it.
const xrayAutoItem = "auto"

func readXrayGroups(running *runningCore) *daemon.Groups {
	var groups daemon.Groups
	overrider, _ := running.xray.GetFeature(xrayRouting.RouterType()).(xrayRouting.BalancerOverrider)
	principle, _ := running.xray.GetFeature(xrayRouting.RouterType()).(xrayRouting.BalancerPrincipleTarget)
	running.access.Lock()
	defer running.access.Unlock()
	for _, balancer := range running.xrayBalancers {
		group := &daemon.Group{Tag: balancer.tag, Type: "urltest", Selectable: true, Selected: xrayAutoItem, IsExpand: coreGroupExpanded(balancer.tag)}
		if overrider != nil {
			if target, err := overrider.GetOverrideTarget(balancer.tag); err == nil && target != "" {
				group.Selected = target
			}
		}
		group.Items = append(group.Items, &daemon.GroupItem{Tag: xrayAutoItem, Type: balancer.strategy})
		if group.Selected == xrayAutoItem && principle != nil {
			if targets, err := principle.GetPrincipleTarget(balancer.tag); err == nil && len(targets) > 0 {
				group.Items[0].Type = balancer.strategy + " → " + targets[0]
			}
		}
		for _, tag := range balancer.members {
			entry := &daemon.GroupItem{Tag: tag, Type: running.xrayProtocols[tag]}
			if result, ok := running.xrayDelays[tag]; ok {
				entry.UrlTestDelay, entry.UrlTestTime = result.delay, result.at.Unix()
			}
			group.Items = append(group.Items, entry)
		}
		groups.Group = append(groups.Group, group)
	}
	return &groups
}

func (s *coreStartedService) SelectOutbound(ctx context.Context, request *daemon.SelectOutboundRequest) (*emptypb.Empty, error) {
	running := otherCore()
	if running == nil {
		return s.StartedService.SelectOutbound(ctx, request)
	}
	switch running.core {
	case CoreMihomo:
		proxy, ok := mihomoTunnel.Proxies()[request.GroupTag]
		if !ok {
			return nil, status.Error(codes.NotFound, "group not found: "+request.GroupTag)
		}
		selectable, ok := proxy.Adapter().(mihomoOutboundGroup.SelectAble)
		if !ok || proxy.Type() != mihomoConstant.Selector {
			return nil, status.Error(codes.FailedPrecondition, "group is not a selector: "+request.GroupTag)
		}
		if err := selectable.Set(request.OutboundTag); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		mihomoCacheFile.Cache().SetSelected(request.GroupTag, request.OutboundTag)
		closeMihomoConnectionsOf(request.GroupTag)
	case CoreXray:
		overrider, ok := running.xray.GetFeature(xrayRouting.RouterType()).(xrayRouting.BalancerOverrider)
		if !ok {
			return nil, status.Error(codes.Unimplemented, "xray router cannot override balancers")
		}
		target := request.OutboundTag
		if target == xrayAutoItem {
			target = ""
		}
		if err := overrider.SetOverrideTarget(request.GroupTag, target); err != nil {
			return nil, status.Error(codes.NotFound, err.Error())
		}
	}
	notifyGroupsChange()
	return &emptypb.Empty{}, nil
}

func closeMihomoConnectionsOf(group string) {
	mihomoStatistic.DefaultManager.Range(func(tracker mihomoStatistic.Tracker) bool {
		for _, name := range tracker.Chains() {
			if name == group {
				_ = tracker.Close()
				break
			}
		}
		return true
	})
}

func (s *coreStartedService) URLTest(ctx context.Context, request *daemon.URLTestRequest) (*emptypb.Empty, error) {
	running := otherCore()
	if running == nil {
		return s.StartedService.URLTest(ctx, request)
	}
	switch running.core {
	case CoreMihomo:
		proxy, ok := mihomoTunnel.Proxies()[request.OutboundTag]
		if !ok {
			return nil, status.Error(codes.NotFound, "outbound not found: "+request.OutboundTag)
		}
		go func() {
			testCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if group, ok := proxy.Adapter().(mihomoOutboundGroup.ProxyGroup); ok {
				_, _ = group.URLTest(testCtx, coreURLTestURL, nil)
			} else {
				_, _ = proxy.URLTest(testCtx, coreURLTestURL, nil)
			}
			notifyGroupsChange()
		}()
	case CoreXray:
		var tags []string
		running.access.Lock()
		for _, balancer := range running.xrayBalancers {
			if balancer.tag == request.OutboundTag {
				tags = append(tags, balancer.members...)
			}
		}
		running.access.Unlock()
		if len(tags) == 0 {
			tags = []string{request.OutboundTag}
		}
		go xrayURLTest(running, tags)
	}
	return &emptypb.Empty{}, nil
}

// xrayURLTest measures each outbound with an HTTP request dialed through it
// (the same way libXray's ping does), at most 8 at a time.
func xrayURLTest(running *runningCore, tags []string) {
	limit := make(chan struct{}, 8)
	var wait sync.WaitGroup
	for _, tag := range tags {
		wait.Add(1)
		limit <- struct{}{}
		go func(tag string) {
			defer wait.Done()
			defer func() { <-limit }()
			delay := xrayMeasure(running.xray, tag)
			running.access.Lock()
			if running.xrayDelays == nil {
				running.xrayDelays = map[string]coreDelay{}
			}
			running.xrayDelays[tag] = coreDelay{delay: delay, at: time.Now()}
			running.access.Unlock()
			notifyGroupsChange()
		}(tag)
	}
	wait.Wait()
}

func xrayMeasure(instance *xrayCore.Instance, tag string) int32 {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				destination, err := xrayNet.ParseDestination(network + ":" + address)
				if err != nil {
					return nil, err
				}
				return xrayCore.Dial(xraySession.SetForcedOutboundTagToContext(ctx, tag), instance, destination)
			},
		},
	}
	// The first request warms up the connection (handshakes); the second is timed.
	for attempt := 0; attempt < 2; attempt++ {
		start := time.Now()
		response, err := client.Get(coreURLTestURL)
		if err != nil {
			return 0
		}
		_ = response.Body.Close()
		if attempt == 1 {
			return int32(time.Since(start).Milliseconds())
		}
	}
	return 0
}

// ---- clash mode (mihomo) ----

var mihomoModes = []string{"Rule", "Global", "Direct"}

func mihomoModeName() string {
	switch mihomoTunnel.Mode() {
	case mihomoTunnel.Global:
		return "Global"
	case mihomoTunnel.Direct:
		return "Direct"
	}
	return "Rule"
}

func (s *coreStartedService) GetClashModeStatus(ctx context.Context, empty *emptypb.Empty) (*daemon.ClashModeStatus, error) {
	running := otherCore()
	if running == nil {
		return s.StartedService.GetClashModeStatus(ctx, empty)
	}
	if running.core != CoreMihomo {
		return &daemon.ClashModeStatus{}, nil
	}
	return &daemon.ClashModeStatus{ModeList: mihomoModes, CurrentMode: mihomoModeName()}, nil
}

func (s *coreStartedService) SubscribeClashMode(empty *emptypb.Empty, server grpc.ServerStreamingServer[daemon.ClashMode]) error {
	return switchStream(server, func(stream grpc.ServerStreamingServer[daemon.ClashMode]) error {
		return s.StartedService.SubscribeClashMode(empty, stream)
	}, func(ctx context.Context, running *runningCore, send func(*daemon.ClashMode) error) error {
		if running.core != CoreMihomo {
			<-ctx.Done()
			return ctx.Err()
		}
		last := ""
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if mode := mihomoModeName(); mode != last {
				last = mode
				if err := send(&daemon.ClashMode{Mode: mode}); err != nil {
					return err
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	})
}

func (s *coreStartedService) SetClashMode(ctx context.Context, request *daemon.ClashMode) (*emptypb.Empty, error) {
	running := otherCore()
	if running == nil {
		return s.StartedService.SetClashMode(ctx, request)
	}
	if running.core != CoreMihomo {
		return nil, status.Error(codes.Unimplemented, "xray has no clash mode")
	}
	mode, ok := mihomoTunnel.ModeMapping[strings.ToLower(request.Mode)]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unknown mode: "+request.Mode)
	}
	mihomoTunnel.SetMode(mode)
	notifyGroupsChange()
	return &emptypb.Empty{}, nil
}

// ---- connections (mihomo; Xray has no connection tracker) ----

func (s *coreStartedService) SubscribeConnections(request *daemon.SubscribeConnectionsRequest, server grpc.ServerStreamingServer[daemon.ConnectionEvents]) error {
	return switchStream(server, func(stream grpc.ServerStreamingServer[daemon.ConnectionEvents]) error {
		return s.StartedService.SubscribeConnections(request, stream)
	}, func(ctx context.Context, running *runningCore, send func(*daemon.ConnectionEvents) error) error {
		if running.core != CoreMihomo && running.xrayTrack == nil {
			return status.Error(codes.Unimplemented, "connection tracking not available")
		}
		interval := time.Duration(request.Interval)
		if interval <= 0 {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		type totals struct{ up, down int64 }
		known := map[string]totals{}
		reset := true
		for {
			var events []*daemon.ConnectionEvent
			seen := map[string]bool{}
			for _, item := range coreConnections(running) {
				id := item.id
				seen[id] = true
				up, down := item.up, item.down
				previous, exists := known[id]
				known[id] = totals{up, down}
				if !exists {
					events = append(events, &daemon.ConnectionEvent{
						Type: daemon.ConnectionEventType_CONNECTION_EVENT_NEW, Id: id, Connection: item.build(),
					})
				} else if up != previous.up || down != previous.down {
					events = append(events, &daemon.ConnectionEvent{
						Type: daemon.ConnectionEventType_CONNECTION_EVENT_UPDATE, Id: id,
						UplinkDelta: up - previous.up, DownlinkDelta: down - previous.down,
					})
				}
			}
			for id := range known {
				if !seen[id] {
					delete(known, id)
					events = append(events, &daemon.ConnectionEvent{
						Type: daemon.ConnectionEventType_CONNECTION_EVENT_CLOSED, Id: id, ClosedAt: time.Now().UnixMilli(),
					})
				}
			}
			if reset || len(events) > 0 {
				if err := send(&daemon.ConnectionEvents{Events: events, Reset_: reset}); err != nil {
					return err
				}
				reset = false
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	})
}

func mihomoConnection(info *mihomoStatistic.TrackerInfo) *daemon.Connection {
	metadata := info.Metadata
	connection := &daemon.Connection{
		Id:            info.UUID.String(),
		Inbound:       metadata.InName,
		InboundType:   strings.ToLower(metadata.Type.String()),
		Network:       strings.ToLower(metadata.NetWork.String()),
		Source:        metadata.SourceAddress(),
		Destination:   metadata.RemoteAddress(),
		Domain:        metadata.Host,
		CreatedAt:     info.Start.UnixMilli(),
		UplinkTotal:   info.UploadTotal.Load(),
		DownlinkTotal: info.DownloadTotal.Load(),
		Rule:          strings.TrimSpace(info.Rule + " " + info.RulePayload),
		ChainList:     info.Chain,
	}
	if metadata.DstIP.Is6() {
		connection.IpVersion = 6
	} else {
		connection.IpVersion = 4
	}
	if len(info.Chain) > 0 {
		connection.Outbound = info.Chain[0]
		if proxy, ok := mihomoTunnel.Proxies()[info.Chain[0]]; ok {
			connection.OutboundType = strings.ToLower(proxy.Type().String())
		}
	}
	return connection
}

func (s *coreStartedService) CloseConnection(ctx context.Context, request *daemon.CloseConnectionRequest) (*emptypb.Empty, error) {
	running := otherCore()
	if running == nil {
		return s.StartedService.CloseConnection(ctx, request)
	}
	if running.core == CoreMihomo {
		if tracker := mihomoStatistic.DefaultManager.Get(request.Id); tracker != nil {
			_ = tracker.Close()
		}
	}
	if running.xrayTrack != nil {
		running.xrayTrack.close(request.Id)
	}
	return &emptypb.Empty{}, nil
}

func (s *coreStartedService) CloseAllConnections(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	running := otherCore()
	if running == nil {
		return s.StartedService.CloseAllConnections(ctx, empty)
	}
	if running.core == CoreMihomo {
		mihomoStatistic.DefaultManager.Range(func(tracker mihomoStatistic.Tracker) bool {
			_ = tracker.Close()
			return true
		})
	}
	if running.xrayTrack != nil {
		running.xrayTrack.closeAll()
	}
	return &emptypb.Empty{}, nil
}

// ---- outbound list (used to pick outbounds in tools) ----

func (s *coreStartedService) SubscribeOutbounds(empty *emptypb.Empty, server grpc.ServerStreamingServer[daemon.OutboundList]) error {
	return switchStream(server, func(stream grpc.ServerStreamingServer[daemon.OutboundList]) error {
		return s.StartedService.SubscribeOutbounds(empty, stream)
	}, func(ctx context.Context, running *runningCore, send func(*daemon.OutboundList) error) error {
		var list daemon.OutboundList
		switch running.core {
		case CoreMihomo:
			var names []string
			for name, proxy := range mihomoTunnel.Proxies() {
				if _, isGroup := proxy.Adapter().(mihomoOutboundGroup.ProxyGroup); !isGroup {
					names = append(names, name)
				}
			}
			sort.Strings(names)
			proxies := mihomoTunnel.Proxies()
			for _, name := range names {
				list.Outbounds = append(list.Outbounds, &daemon.GroupItem{Tag: name, Type: strings.ToLower(proxies[name].Type().String())})
			}
		case CoreXray:
			running.access.Lock()
			for _, tag := range running.xrayOutboundTags {
				list.Outbounds = append(list.Outbounds, &daemon.GroupItem{Tag: tag, Type: running.xrayProtocols[tag]})
			}
			running.access.Unlock()
		}
		if err := send(&list); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
}

type coreConnectionItem struct {
	id       string
	up, down int64
	build    func() *daemon.Connection
}

// coreConnections lists the running core's live connections (mihomo's
// statistic manager, or the Xray tracker).
func coreConnections(running *runningCore) []coreConnectionItem {
	var items []coreConnectionItem
	if running.core == CoreMihomo {
		for _, info := range mihomoStatistic.DefaultManager.Snapshot().Connections {
			info := info
			items = append(items, coreConnectionItem{
				id: info.UUID.String(), up: info.UploadTotal.Load(), down: info.DownloadTotal.Load(),
				build: func() *daemon.Connection { return mihomoConnection(info) },
			})
		}
	} else if running.xrayTrack != nil {
		running.access.Lock()
		protocols := running.xrayProtocols
		running.access.Unlock()
		for _, conn := range running.xrayTrack.snapshot() {
			conn := conn
			items = append(items, coreConnectionItem{
				id: conn.id, up: conn.up.Load(), down: conn.down.Load(),
				build: func() *daemon.Connection { return conn.connection(protocols) },
			})
		}
	}
	return items
}
