//go:build !(android && cmfa)

package libbox

// UpdateCoreSystemDNS is only needed by mihomo built for Android with the
// cmfa tag; elsewhere mihomo reads the system resolver itself.
func UpdateCoreSystemDNS(servers string) {}
