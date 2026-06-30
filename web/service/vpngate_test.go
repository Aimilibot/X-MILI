package service

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestParseVPNGateProtoPort(t *testing.T) {
	config := base64.StdEncoding.EncodeToString([]byte("client\nproto tcp\nremote 1.2.3.4 443 tcp\n"))
	proto, port := parseVPNGateProtoPort(config)
	if proto != "tcp" || port != "443" {
		t.Fatalf("got %s/%s", proto, port)
	}
}

func TestParseVPNGateCSV(t *testing.T) {
	config := base64.StdEncoding.EncodeToString([]byte("client\nproto udp\nremote 1.2.3.4 1194\n"))
	body := "prefix\n#HostName,IP,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n" +
		"host,1.2.3.4,Japan,JP,7," + config + "\n*\n"

	servers, err := parseVPNGateCSV(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers", len(servers))
	}
	if servers[0].CountryShortLower != "jp" || servers[0].Port != "1194" || servers[0].NumSessions != 7 {
		t.Fatalf("unexpected server: %+v", servers[0])
	}
}

func TestListServersReturnsCachedCopy(t *testing.T) {
	vpnGateCache.Lock()
	oldServers, oldExpires := vpnGateCache.servers, vpnGateCache.expires
	vpnGateCache.servers = []VPNGateServer{{IP: "1.2.3.4"}}
	vpnGateCache.expires = time.Now().Add(time.Minute)
	vpnGateCache.Unlock()
	defer func() {
		vpnGateCache.Lock()
		vpnGateCache.servers, vpnGateCache.expires = oldServers, oldExpires
		vpnGateCache.Unlock()
	}()

	service := &VPNGateService{}
	servers, err := service.ListServers(false)
	if err != nil {
		t.Fatal(err)
	}
	servers[0].IP = "changed"

	servers, err = service.ListServers(false)
	if err != nil {
		t.Fatal(err)
	}
	if servers[0].IP != "1.2.3.4" {
		t.Fatalf("cache was mutated: %+v", servers[0])
	}
}

func TestListServersCanIncludeUnavailableFromCache(t *testing.T) {
	vpnGateCache.Lock()
	oldServers, oldExpires := vpnGateCache.servers, vpnGateCache.expires
	vpnGateCache.servers = []VPNGateServer{{IP: "1.2.3.4", LocalPing: 10}, {IP: "5.6.7.8", LocalPing: -1}}
	vpnGateCache.expires = time.Now().Add(time.Minute)
	vpnGateCache.Unlock()
	defer func() {
		vpnGateCache.Lock()
		vpnGateCache.servers, vpnGateCache.expires = oldServers, oldExpires
		vpnGateCache.Unlock()
	}()

	service := &VPNGateService{}
	servers, err := service.ListServers(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected available servers: %+v", servers)
	}

	servers, err = service.ListServersWithUnavailable(false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("unexpected all servers: %+v", servers)
	}
}

func TestSanitizeVPNGateOpenVPNConfig(t *testing.T) {
	raw := "client\nscript-security 2\nup /tmp/pwn\nremote 1.2.3.4 1194\n<ca>\nup is just cert text\n</ca>\n"
	config := base64.StdEncoding.EncodeToString([]byte(raw))

	got, err := sanitizeVPNGateOpenVPNConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "script-security") || strings.Contains(got, "up /tmp/pwn") {
		t.Fatalf("dangerous directive survived:\n%s", got)
	}
	if !strings.Contains(got, "remote 1.2.3.4 1194") || !strings.Contains(got, "up is just cert text") {
		t.Fatalf("safe content was removed:\n%s", got)
	}
	if !strings.Contains(got, "route-nopull") {
		t.Fatalf("route-nopull missing:\n%s", got)
	}
}

func TestBuildVPNGateOutbound(t *testing.T) {
	outbound := buildVPNGateOutbound("10.8.0.2")
	if outbound["tag"] != "vpngate" || outbound["protocol"] != "freedom" || outbound["sendThrough"] != "10.8.0.2" {
		t.Fatalf("unexpected outbound: %+v", outbound)
	}
}

func TestVPNGateOpenVPNCheckRejectsBadConfig(t *testing.T) {
	if testVPNGateOpenVPN(VPNGateServer{OpenVPNConfig: "bad"}) {
		t.Fatalf("bad OpenVPN config was accepted")
	}
}

func TestNormalizeVPNGateRuleMode(t *testing.T) {
	if got := normalizeVPNGateRuleMode("fixed"); got != "fixed" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeVPNGateRuleMode("favorite"); got != "favorite" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeVPNGateRuleMode(""); got != "default" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeVPNGateRuleMode("bad"); got != "default" {
		t.Fatalf("got %q", got)
	}
}

func TestChooseOpenVPNTunRejectsReusedSingleTun(t *testing.T) {
	_, _, ok := chooseOpenVPNTun(
		map[string]string{"tun0": "10.8.0.2"},
		map[string]string{"tun0": "10.8.0.2"},
	)
	if ok {
		t.Fatalf("expected tun to be rejected because it is reused with the same IP")
	}
}

func TestFilterVPNGateCandidatesSkipsCurrentAndTemporarilyFailed(t *testing.T) {
	now := time.Now()
	current := &VPNGateServer{IP: "1.1.1.1"}
	servers := []VPNGateServer{
		{IP: "1.1.1.1"},
		{IP: "2.2.2.2"},
		{IP: "3.3.3.3"},
	}
	failedUntil := map[string]time.Time{
		"2.2.2.2": now.Add(time.Minute),
		"3.3.3.3": now.Add(-time.Minute),
	}

	got := filterVPNGateCandidates(servers, current, failedUntil, now)
	if len(got) != 1 || got[0].IP != "3.3.3.3" {
		t.Fatalf("unexpected candidates: %+v", got)
	}
}
