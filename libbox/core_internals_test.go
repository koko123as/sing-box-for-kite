package libbox

// Guards for the Xray and mihomo internals libbox reaches into. A core
// upgrade that moves one of these fails here instead of on a device.

import (
	"reflect"
	"testing"

	mihomoListenerConfig "github.com/metacubex/mihomo/listener/config"
	xrayRouting "github.com/xtls/xray-core/features/routing"
	xrayTun "github.com/xtls/xray-core/proxy/tun"
)

// The connection list wraps the TUN handler's private dispatcher field.
func TestCoreInternalsXrayTunDispatcher(t *testing.T) {
	field, ok := reflect.TypeOf(xrayTun.Handler{}).FieldByName("dispatcher")
	if !ok {
		t.Fatal("xray proxy/tun.Handler has no dispatcher field: Xray connection list and traffic would be empty")
	}
	if want := reflect.TypeOf((*xrayRouting.Dispatcher)(nil)).Elem(); field.Type != want {
		t.Fatalf("dispatcher field is %v, want %v", field.Type, want)
	}
}

// mihomo gets the TUN as a file descriptor in its tun config.
func TestCoreInternalsMihomoTunFileDescriptor(t *testing.T) {
	if _, ok := reflect.TypeOf(mihomoListenerConfig.Tun{}).FieldByName("FileDescriptor"); !ok {
		t.Fatal("mihomo listener/config.Tun has no FileDescriptor field")
	}
}
