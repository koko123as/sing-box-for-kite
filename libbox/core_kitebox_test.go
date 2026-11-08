package libbox

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// A subscription serving several configs becomes one profile per config,
// even when Xray elements could be merged into one.
func TestCoreConfigArrayEach(t *testing.T) {
	node := func(remarks, address string) string {
		config := testMasqueConfig(t, remarks)
		proxy := config["outbounds"].([]any)[0].(map[string]any)
		proxy["settings"].(map[string]any)["address"] = address
		return mustJSON(t, config)
	}
	content := "[" + node("Node A", "203.0.113.20") + "," + node("Node B", "203.0.113.21") + "," + `{"remarks":"SB","outbounds":[{"type":"direct","tag":"direct"}]}` + "]"
	entries, err := SplitCoreConfigArrayEach(content)
	if err != nil {
		t.Fatal(err)
	}
	if entries.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", entries.Len())
	}
	wantCores := []string{CoreXray, CoreXray, CoreSingBox}
	wantRemarks := []string{"Node A", "Node B", "SB"}
	for i := int32(0); i < entries.Len(); i++ {
		if entries.Core(i) != wantCores[i] || entries.Remarks(i) != wantRemarks[i] {
			t.Fatalf("entry %d: core %s remarks %q", i, entries.Core(i), entries.Remarks(i))
		}
		if err := CheckCoreConfig(entries.Core(i), entries.Content(i)); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if strings.Contains(entries.Content(2), "remarks") {
		t.Fatal("sing-box entry keeps remarks")
	}
}

// Check errors name the core that rejected the profile.
func TestCoreErrorNamesCore(t *testing.T) {
	for core, content := range map[string]string{
		CoreSingBox: `{"outbounds":[{"type":"no-such-type"}]}`,
		CoreXray:    `{"outbounds":[{"protocol":"no-such-protocol"}]}`,
		CoreMihomo:  "proxies:\n  - {name: a, type: no-such-type, server: 1.1.1.1, port: 1}\nrules:\n  - MATCH,a\n",
	} {
		err := CheckCoreConfig(core, content)
		if err == nil {
			t.Fatalf("%s: invalid config accepted", core)
		}
		if !strings.HasPrefix(err.Error(), CoreDisplayName(core)+": ") {
			t.Fatalf("%s: error does not name the core: %v", core, err)
		}
	}
}

type fakeStream[T any] struct {
	ctx  context.Context
	sent atomic.Int32
}

func (s *fakeStream[T]) Send(*T) error                { s.sent.Add(1); return nil }
func (s *fakeStream[T]) SetHeader(metadata.MD) error  { return nil }
func (s *fakeStream[T]) SendHeader(metadata.MD) error { return nil }
func (s *fakeStream[T]) SetTrailer(metadata.MD)       {}
func (s *fakeStream[T]) Context() context.Context     { return s.ctx }
func (s *fakeStream[T]) SendMsg(any) error            { return nil }
func (s *fakeStream[T]) RecvMsg(any) error            { return nil }

// A sing-box-only status stream opened while no core runs (the gap of a
// profile switch) retries silently instead of failing with "invalid argument".
func TestIdleWhileOtherCoreRetriesDuringSwitch(t *testing.T) {
	saved := singBoxRetryInterval
	singBoxRetryInterval = 10 * time.Millisecond
	defer func() { singBoxRetryInterval = saved }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := &fakeStream[struct{}]{ctx: ctx}
	var calls atomic.Int32
	err := idleWhileOtherCore[struct{}](stream, func(server grpc.ServerStreamingServer[struct{}]) error {
		if calls.Add(1) < 3 {
			return os.ErrInvalid
		}
		return server.Send(&struct{}{})
	})
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	if calls.Load() != 3 || stream.sent.Load() != 1 {
		t.Fatalf("calls %d sent %d", calls.Load(), stream.sent.Load())
	}

	// Other errors still reach the client.
	err = idleWhileOtherCore[struct{}](stream, func(grpc.ServerStreamingServer[struct{}]) error {
		return os.ErrPermission
	})
	if err != os.ErrPermission {
		t.Fatalf("unexpected: %v", err)
	}

	// The client going away ends the wait.
	short, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	err = idleWhileOtherCore[struct{}](&fakeStream[struct{}]{ctx: short}, func(grpc.ServerStreamingServer[struct{}]) error {
		return os.ErrInvalid
	})
	if err == nil {
		t.Fatal("stream did not end with its context")
	}
}
