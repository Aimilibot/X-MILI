package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

const (
	vpnGateOutboundTag = "vpngate"
	vpnGateRouteTable  = "10077"
)

type OpenVPNService struct{}

type OpenVPNStatus struct {
	Phase    string         `json:"phase"`
	Progress int            `json:"progress"`
	Message  string         `json:"message"`
	Error    string         `json:"error,omitempty"`
	TunIP    string         `json:"tunIP,omitempty"`
	TunDev   string         `json:"tunDev,omitempty"`
	Outbound map[string]any `json:"outbound,omitempty"`
	Server   *VPNGateServer `json:"server,omitempty"`
	Log      []string       `json:"log,omitempty"`
}

type openVPNTask struct {
	sync.Mutex
	id                int64
	cancel            context.CancelFunc
	cmd               *exec.Cmd
	status            OpenVPNStatus
	ruleMode          string
	selectedCountries []string
	fallbackEnable    bool
}

var vpnGateOpenVPN = &openVPNTask{
	status: OpenVPNStatus{
		Phase:    "idle",
		Progress: 0,
		Message:  "未连接",
	},
}

func (s *OpenVPNService) StartVPNGate(server VPNGateServer, ruleMode string, selectedCountries []string, fallbackEnable bool) (*OpenVPNStatus, error) {
	if server.OpenVPNConfig == "" {
		return nil, errors.New("OpenVPN config is empty")
	}
	ctx, cancel := context.WithCancel(context.Background())

	vpnGateOpenVPN.Lock()
	vpnGateOpenVPN.stopLocked()
	vpnGateOpenVPN.id++
	taskID := vpnGateOpenVPN.id
	vpnGateOpenVPN.cancel = cancel
	vpnGateOpenVPN.ruleMode = ruleMode
	vpnGateOpenVPN.selectedCountries = selectedCountries
	vpnGateOpenVPN.fallbackEnable = fallbackEnable
	vpnGateOpenVPN.status = OpenVPNStatus{
		Phase:    "installing",
		Progress: 8,
		Message:  "正在检查 OpenVPN",
		Server:   &server,
	}
	vpnGateOpenVPN.Unlock()

	go s.connectVPNGate(ctx, taskID, server)
	status := s.VPNGateStatus()
	return &status, nil
}

func (s *OpenVPNService) VPNGateStatus() OpenVPNStatus {
	vpnGateOpenVPN.Lock()
	defer vpnGateOpenVPN.Unlock()
	return cloneOpenVPNStatus(vpnGateOpenVPN.status)
}

func (s *OpenVPNService) CancelVPNGate() OpenVPNStatus {
	vpnGateOpenVPN.Lock()
	defer vpnGateOpenVPN.Unlock()
	vpnGateOpenVPN.stopLocked()
	vpnGateOpenVPN.status.Phase = "canceled"
	vpnGateOpenVPN.status.Progress = 0
	vpnGateOpenVPN.status.Message = "已取消"
	vpnGateOpenVPN.status.Error = ""
	vpnGateOpenVPN.status.TunIP = ""
	vpnGateOpenVPN.status.TunDev = ""
	vpnGateOpenVPN.status.Outbound = nil
	return cloneOpenVPNStatus(vpnGateOpenVPN.status)
}

func (s *OpenVPNService) StopVPNGate() OpenVPNStatus {
	return s.CancelVPNGate()
}

func (s *OpenVPNService) connectVPNGate(ctx context.Context, taskID int64, server VPNGateServer) {
	if runtime.GOOS != "linux" {
		vpnGateOpenVPN.fail(taskID, "OpenVPN 托管连接仅支持 Linux")
		return
	}
	if err := ensureOpenVPNInstalled(ctx, taskID); err != nil {
		vpnGateOpenVPN.fail(taskID, err.Error())
		return
	}

	vpnGateOpenVPN.setTask(taskID, "preparing", 30, "正在清洗配置")
	ovpn, err := sanitizeVPNGateOpenVPNConfig(server.OpenVPNConfig)
	if err != nil {
		vpnGateOpenVPN.fail(taskID, err.Error())
		return
	}
	workDir := filepath.Join(config.GetBinFolderPath(), "vpngate")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		vpnGateOpenVPN.fail(taskID, err.Error())
		return
	}
	configPath := filepath.Join(workDir, "active.ovpn")
	if err := os.WriteFile(configPath, []byte(ovpn), 0o600); err != nil {
		vpnGateOpenVPN.fail(taskID, err.Error())
		return
	}
	beforeTun, err := listOpenVPNTun()
	if err != nil {
		vpnGateOpenVPN.fail(taskID, err.Error())
		return
	}

	vpnGateOpenVPN.setTask(taskID, "connecting", 45, "正在尝试连接")
	cmd := exec.CommandContext(ctx, "openvpn", "--config", configPath, "--route-nopull", "--auth-nocache", "--verb", "3")
	writer := &openVPNLogWriter{}
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err := cmd.Start(); err != nil {
		vpnGateOpenVPN.fail(taskID, err.Error())
		return
	}
	vpnGateOpenVPN.Lock()
	if vpnGateOpenVPN.id != taskID {
		vpnGateOpenVPN.Unlock()
		_ = cmd.Process.Kill()
		return
	}
	vpnGateOpenVPN.cmd = cmd
	vpnGateOpenVPN.Unlock()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	deadline := time.After(45 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			vpnGateOpenVPN.setTask(taskID, "canceled", 0, "已取消")
			return
		case err := <-done:
			vpnGateOpenVPN.Lock()
			phase := vpnGateOpenVPN.status.Phase
			vpnGateOpenVPN.Unlock()
			if phase == "connected" {
				go triggerVPNGateFailover(taskID)
			} else {
				if err == nil {
					vpnGateOpenVPN.fail(taskID, "OpenVPN 已退出")
				} else {
					vpnGateOpenVPN.fail(taskID, err.Error())
				}
			}
			return
		case <-deadline:
			vpnGateOpenVPN.fail(taskID, "OpenVPN 连接超时")
			return
		case <-ticker.C:
			vpnGateOpenVPN.appendLog(writer.lines())
			if writer.contains("Initialization Sequence Completed") {
				tunIP, tunDev, err := detectOpenVPNTun(beforeTun)
				if err != nil {
					vpnGateOpenVPN.fail(taskID, err.Error())
					return
				}
				if err := setupOpenVPNPolicyRoute(tunIP, tunDev); err != nil {
					vpnGateOpenVPN.fail(taskID, err.Error())
					return
				}
				outbound := buildVPNGateOutbound(tunIP)
				if err := updateXrayVPNGateOutbound(outbound); err != nil {
					vpnGateOpenVPN.fail(taskID, fmt.Sprintf("Xray配置更新失败: %v", err))
					return
				}

				vpnGateOpenVPN.Lock()
				if vpnGateOpenVPN.id != taskID {
					vpnGateOpenVPN.Unlock()
					return
				}
				vpnGateOpenVPN.status.Phase = "connected"
				vpnGateOpenVPN.status.Progress = 100
				vpnGateOpenVPN.status.Message = "连接成功"
				vpnGateOpenVPN.status.TunIP = tunIP
				vpnGateOpenVPN.status.TunDev = tunDev
				vpnGateOpenVPN.status.Outbound = outbound
				vpnGateOpenVPN.Unlock()

				writer.Lock()
				writer.closed = true
				writer.buf = ""
				writer.linesBuf = nil
				writer.all = ""
				writer.Unlock()

				go func() {
					err := <-done
					vpnGateOpenVPN.Lock()
					phase := vpnGateOpenVPN.status.Phase
					vpnGateOpenVPN.Unlock()
					if phase == "connected" {
						go triggerVPNGateFailover(taskID)
					} else {
						msg := "OpenVPN 已断开"
						if err != nil {
							msg += ": " + err.Error()
						}
						vpnGateOpenVPN.fail(taskID, msg)
					}
				}()

				// Spawn network watchdog checker
				go startNetworkChecker(ctx, taskID, tunIP, tunDev)
				return
			}
			if writer.contains("AUTH_FAILED") {
				vpnGateOpenVPN.fail(taskID, "OpenVPN 认证失败")
				return
			}
		}
	}
}

func sanitizeVPNGateOpenVPNConfig(base64Config string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64Config)
	if err != nil {
		return "", err
	}
	blocked := map[string]bool{
		"askpass":               true,
		"auth-user-pass-verify": true,
		"cd":                    true,
		"client-connect":        true,
		"client-disconnect":     true,
		"daemon":                true,
		"down":                  true,
		"ipchange":              true,
		"learn-address":         true,
		"log":                   true,
		"log-append":            true,
		"management":            true,
		"plugin":                true,
		"route-pre-down":        true,
		"route-up":              true,
		"script-security":       true,
		"status":                true,
		"tls-verify":            true,
		"up":                    true,
		"writepid":              true,
	}

	var out []string
	inInline := false
	scanner := bufio.NewScanner(bytes.NewReader(decoded))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "</") {
			inInline = false
			out = append(out, line)
			continue
		}
		if strings.HasPrefix(lower, "<") {
			inInline = true
			out = append(out, line)
			continue
		}
		if inInline || trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			out = append(out, line)
			continue
		}
		name := strings.ToLower(strings.Fields(trimmed)[0])
		if blocked[name] {
			continue
		}
		if name == "route-nopull" {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	out = append(out, "route-nopull")
	return strings.Join(out, "\n") + "\n", nil
}

func ensureOpenVPNInstalled(ctx context.Context, taskID int64) error {
	if _, err := exec.LookPath("openvpn"); err == nil {
		vpnGateOpenVPN.setTask(taskID, "installing", 20, "OpenVPN 已安装")
		return nil
	}
	vpnGateOpenVPN.setTask(taskID, "installing", 12, "正在安装 OpenVPN")
	switch {
	case commandExists("apt-get"):
		if err := runCommand(ctx, "apt-get", "update"); err != nil {
			return err
		}
		return runCommand(ctx, "apt-get", "install", "-y", "openvpn")
	case commandExists("dnf"):
		return runCommand(ctx, "dnf", "install", "-y", "openvpn")
	case commandExists("yum"):
		return runCommand(ctx, "yum", "install", "-y", "openvpn")
	case commandExists("apk"):
		return runCommand(ctx, "apk", "add", "--no-cache", "openvpn")
	case commandExists("pacman"):
		return runCommand(ctx, "pacman", "-Sy", "--noconfirm", "openvpn")
	default:
		return errors.New("未找到支持的包管理器，请手动安装 openvpn")
	}
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	vpnGateOpenVPN.addLog(strings.TrimSpace(string(out)))
	if err != nil {
		return fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func listOpenVPNTun() (map[string]string, error) {
	out, err := exec.Command("ip", "-o", "-4", "addr", "show").Output()
	if err != nil {
		return nil, err
	}
	tuns := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		dev := strings.TrimSuffix(fields[1], ":")
		if !strings.HasPrefix(dev, "tun") && !strings.HasPrefix(dev, "tap") {
			continue
		}
		var ip net.IP
		if strings.Contains(fields[3], "/") {
			ip, _, _ = net.ParseCIDR(fields[3])
		} else {
			ip = net.ParseIP(fields[3])
		}
		if ip != nil && ip.To4() != nil {
			tuns[dev] = ip.String()
		}
	}
	return tuns, nil
}

func detectOpenVPNTun(before map[string]string) (string, string, error) {
	var lastErr error
	for i := 0; i < 12; i++ {
		after, err := listOpenVPNTun()
		if err != nil {
			lastErr = err
		} else if ip, dev, ok := chooseOpenVPNTun(before, after); ok {
			return ip, dev, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return "", "", lastErr
	}
	return "", "", errors.New("未找到 OpenVPN tun IPv4 地址")
}

func chooseOpenVPNTun(before, after map[string]string) (string, string, bool) {
	for dev, ip := range after {
		if oldIP, ok := before[dev]; !ok || oldIP != ip {
			return ip, dev, true
		}
	}
	return "", "", false
}

func setupOpenVPNPolicyRoute(tunIP, tunDev string) error {
	_ = runCommand(context.Background(), "ip", "rule", "del", "from", tunIP, "table", vpnGateRouteTable)
	if err := runCommand(context.Background(), "ip", "route", "replace", "default", "dev", tunDev, "table", vpnGateRouteTable); err != nil {
		return err
	}
	if err := runCommand(context.Background(), "ip", "rule", "add", "from", tunIP, "table", vpnGateRouteTable); err != nil {
		return err
	}
	_ = runCommand(context.Background(), "ip", "route", "flush", "cache")
	return nil
}

func cleanupOpenVPNPolicyRoute(tunIP string) {
	if tunIP == "" {
		return
	}
	_ = runCommandQuiet(context.Background(), "ip", "rule", "del", "from", tunIP, "table", vpnGateRouteTable)
	_ = runCommandQuiet(context.Background(), "ip", "route", "flush", "table", vpnGateRouteTable)
	_ = runCommandQuiet(context.Background(), "ip", "route", "flush", "cache")
}

func runCommandQuiet(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

func buildVPNGateOutbound(tunIP string) map[string]any {
	return map[string]any{
		"tag":         vpnGateOutboundTag,
		"protocol":    "freedom",
		"sendThrough": tunIP,
		"settings": map[string]any{
			"domainStrategy": "UseIP",
		},
	}
}

func (t *openVPNTask) setTask(taskID int64, phase string, progress int, message string) {
	t.Lock()
	defer t.Unlock()
	if t.id != taskID {
		return
	}
	t.status.Phase = phase
	t.status.Progress = progress
	t.status.Message = message
	t.status.Error = ""
}

func (t *openVPNTask) fail(taskID int64, message string) {
	t.Lock()
	defer t.Unlock()
	if t.id != taskID || t.status.Phase == "canceled" {
		return
	}
	t.stopLocked()
	t.status.Phase = "failed"
	t.status.Progress = 0
	t.status.Message = message
	t.status.Error = message
	t.status.Outbound = nil
	t.status.TunIP = ""
	t.status.TunDev = ""
}

func (t *openVPNTask) stopLocked() {
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
		t.cmd = nil
	}
	cleanupOpenVPNPolicyRoute(t.status.TunIP)
}

func (t *openVPNTask) addLog(line string) {
	if line == "" {
		return
	}
	t.Lock()
	defer t.Unlock()
	t.status.Log = append(t.status.Log, line)
	if len(t.status.Log) > 80 {
		t.status.Log = t.status.Log[len(t.status.Log)-80:]
	}
}

func (t *openVPNTask) appendLog(lines []string) {
	for _, line := range lines {
		t.addLog(line)
	}
}

func cloneOpenVPNStatus(status OpenVPNStatus) OpenVPNStatus {
	status.Log = append([]string(nil), status.Log...)
	if status.Outbound != nil {
		raw, _ := json.Marshal(status.Outbound)
		var clone map[string]any
		_ = json.Unmarshal(raw, &clone)
		status.Outbound = clone
	}
	if status.Server != nil {
		server := *status.Server
		status.Server = &server
	}
	return status
}

type openVPNLogWriter struct {
	sync.Mutex
	buf      string
	linesBuf []string
	all      string
	closed   bool
}

func (w *openVPNLogWriter) Write(p []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	if w.closed {
		return len(p), nil
	}
	w.buf += string(p)
	for {
		i := strings.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(w.buf[:i])
		w.buf = w.buf[i+1:]
		if line != "" {
			w.linesBuf = append(w.linesBuf, line)
			w.all += line + "\n"
		}
	}
	return len(p), nil
}

func (w *openVPNLogWriter) lines() []string {
	w.Lock()
	defer w.Unlock()
	lines := append([]string(nil), w.linesBuf...)
	w.linesBuf = nil
	return lines
}

func (w *openVPNLogWriter) contains(text string) bool {
	w.Lock()
	defer w.Unlock()
	return strings.Contains(w.all, text)
}

func startNetworkChecker(ctx context.Context, taskID int64, tunIP, tunDev string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	failCount := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			vpnGateOpenVPN.Lock()
			currentID := vpnGateOpenVPN.id
			phase := vpnGateOpenVPN.status.Phase
			vpnGateOpenVPN.Unlock()

			if currentID != taskID || phase != "connected" {
				return
			}

			// Perform health check: ping 8.8.8.8 through the tun interface
			cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "3", "-I", tunDev, "8.8.8.8")
			if err := cmd.Run(); err != nil {
				failCount++
				logger.Warningf("[VPNGate Watchdog] Ping test failed on %s (count %d): %v", tunDev, failCount, err)
			} else {
				failCount = 0
			}

			if failCount >= 3 {
				logger.Errorf("[VPNGate Watchdog] VPNGate connection on %s is dead. Triggering auto-failover...", tunDev)
				go triggerVPNGateFailover(taskID)
				return
			}
		}
	}
}

func triggerVPNGateFailover(taskID int64) {
	vpnGateOpenVPN.Lock()
	if vpnGateOpenVPN.id != taskID {
		vpnGateOpenVPN.Unlock()
		return
	}
	ruleMode := vpnGateOpenVPN.ruleMode
	selectedCountries := vpnGateOpenVPN.selectedCountries
	fallbackEnable := vpnGateOpenVPN.fallbackEnable
	currentServer := vpnGateOpenVPN.status.Server

	if ruleMode == "" {
		vpnGateOpenVPN.fail(taskID, "VPNGate 连接断开，且无后备过滤规则")
		vpnGateOpenVPN.Unlock()
		return
	}

	vpnGateOpenVPN.stopLocked()
	vpnGateOpenVPN.status.Phase = "connecting"
	vpnGateOpenVPN.status.Message = "检测到节点失效，正在自动选择后备节点"
	vpnGateOpenVPN.status.Progress = 50
	vpnGateOpenVPN.Unlock()

	// 1. Fetch fresh list of servers
	vpngateService := &VPNGateService{}
	servers, err := vpngateService.ListServers(true)
	if err != nil {
		vpnGateOpenVPN.fail(taskID, fmt.Sprintf("自动候补失败: 无法获取节点列表 (%v)", err))
		return
	}

	// Load favorites from settings DB
	settingService := &SettingService{}
	favStr, err := settingService.GetVPNGateFavorites()
	if err != nil {
		favStr = "[]"
	}
	var favorites []string
	_ = json.Unmarshal([]byte(favStr), &favorites)

	// 2. Filter servers based on ruleMode & selectedCountries
	var pool []VPNGateServer
	if ruleMode == "fixed" {
		for _, s := range servers {
			if containsString(selectedCountries, s.CountryShort) {
				pool = append(pool, s)
			}
		}
		if len(pool) == 0 {
			if fallbackEnable {
				pool = servers
			} else {
				vpnGateOpenVPN.fail(taskID, "所有选定国家节点均已失效且关闭了候补连接")
				return
			}
		}
	} else if ruleMode == "favorite" {
		for _, s := range servers {
			if containsString(favorites, s.HostName) {
				pool = append(pool, s)
			}
		}
		if len(pool) == 0 {
			if fallbackEnable {
				pool = servers
			} else {
				vpnGateOpenVPN.fail(taskID, "所有收藏节点均已失效且关闭了候补连接")
				return
			}
		}
	} else {
		pool = servers
	}

	// Filter out the failed server IP
	var candidates []VPNGateServer
	if currentServer != nil {
		for _, s := range pool {
			if s.IP != currentServer.IP {
				candidates = append(candidates, s)
			}
		}
	} else {
		candidates = pool
	}

	if len(candidates) == 0 {
		if (ruleMode == "favorite" || ruleMode == "fixed") && fallbackEnable && len(pool) < len(servers) {
			for _, s := range servers {
				if currentServer == nil || s.IP != currentServer.IP {
					candidates = append(candidates, s)
				}
			}
		}
	}

	if len(candidates) == 0 {
		vpnGateOpenVPN.fail(taskID, "自动候补失败: 无可用后备节点")
		return
	}

	// 3. Sort by ping Rank (lowest ping first)
	sort.Slice(candidates, func(i, j int) bool {
		pi := candidates[i].LocalPing
		pj := candidates[j].LocalPing
		if pi < 0 {
			pi = 999999
		}
		if pj < 0 {
			pj = 999999
		}
		return pi < pj
	})

	best := candidates[0]

	vpnGateOpenVPN.Lock()
	if vpnGateOpenVPN.id != taskID {
		vpnGateOpenVPN.Unlock()
		return
	}
	vpnGateOpenVPN.status.Server = &best
	vpnGateOpenVPN.status.Message = fmt.Sprintf("正在尝试连接候补节点 [%s - %s]", best.CountryLong, best.IP)

	ctx, cancel := context.WithCancel(context.Background())
	vpnGateOpenVPN.cancel = cancel
	vpnGateOpenVPN.Unlock()

	openvpnService := &OpenVPNService{}
	go openvpnService.connectVPNGate(ctx, taskID, best)
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func updateXrayVPNGateOutbound(outbound map[string]any) error {
	settingService := &SettingService{}
	xraySettingService := &XraySettingService{}
	xrayService := &XrayService{}

	// 1. Get template config
	templateConfig, err := settingService.GetXrayConfigTemplate()
	if err != nil {
		return err
	}

	// 2. Parse config JSON
	var configMap map[string]any
	if err := json.Unmarshal([]byte(templateConfig), &configMap); err != nil {
		return err
	}

	// 3. Find and update outbound with tag "vpngate"
	outboundsVal, ok := configMap["outbounds"]
	if !ok {
		return fmt.Errorf("outbounds key not found in template config")
	}
	outbounds, ok := outboundsVal.([]any)
	if !ok {
		return fmt.Errorf("outbounds is not an array")
	}

	found := false
	for i, o := range outbounds {
		oMap, ok := o.(map[string]any)
		if !ok {
			continue
		}
		if tag, ok := oMap["tag"].(string); ok && tag == vpnGateOutboundTag {
			outbounds[i] = outbound
			found = true
			break
		}
	}
	if !found {
		outbounds = append(outbounds, outbound)
	}
	configMap["outbounds"] = outbounds

	// 4. Serialize back
	newConfigBytes, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return err
	}

	// 5. Save settings
	if err := xraySettingService.SaveXraySetting(string(newConfigBytes)); err != nil {
		return err
	}

	// 6. Restart Xray
	return xrayService.RestartXray(true)
}

func (s *OpenVPNService) UninstallVPNGate() error {
	// 1. Cancel/stop any running openvpn tasks
	vpnGateOpenVPN.Lock()
	vpnGateOpenVPN.stopLocked()
	vpnGateOpenVPN.status.Phase = "idle"
	vpnGateOpenVPN.status.Progress = 0
	vpnGateOpenVPN.status.Message = "未连接"
	vpnGateOpenVPN.status.Error = ""
	vpnGateOpenVPN.status.TunIP = ""
	vpnGateOpenVPN.status.TunDev = ""
	vpnGateOpenVPN.status.Outbound = nil
	vpnGateOpenVPN.Unlock()

	// 2. Perform package purging on Linux
	if runtime.GOOS == "linux" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		var err error
		switch {
		case commandExists("apt-get"):
			err = runCommand(ctx, "apt-get", "purge", "-y", "openvpn")
			if err == nil {
				_ = runCommand(ctx, "apt-get", "autoremove", "-y")
			}
		case commandExists("dnf"):
			err = runCommand(ctx, "dnf", "remove", "-y", "openvpn")
		case commandExists("yum"):
			err = runCommand(ctx, "yum", "remove", "-y", "openvpn")
		case commandExists("apk"):
			err = runCommand(ctx, "apk", "del", "openvpn")
		case commandExists("pacman"):
			err = runCommand(ctx, "pacman", "-Rns", "--noconfirm", "openvpn")
		default:
			err = errors.New("unsupported package manager for uninstallation")
		}
		if err != nil {
			logger.Warningf("[VPNGate] Failed to uninstall openvpn package: %v", err)
		}
	}

	// 3. Clear node information (servers list cache)
	vpngateService := &VPNGateService{}
	vpngateService.ClearCache()

	// 4. Remove outbound tag "vpngate" from xray template
	_ = removeXrayVPNGateOutbound()

	return nil
}

func removeXrayVPNGateOutbound() error {
	settingService := &SettingService{}
	xraySettingService := &XraySettingService{}
	xrayService := &XrayService{}

	templateConfig, err := settingService.GetXrayConfigTemplate()
	if err != nil {
		return err
	}

	var configMap map[string]any
	if err := json.Unmarshal([]byte(templateConfig), &configMap); err != nil {
		return err
	}

	outboundsVal, ok := configMap["outbounds"]
	if !ok {
		return nil
	}
	outbounds, ok := outboundsVal.([]any)
	if !ok {
		return nil
	}

	var newOutbounds []any
	for _, o := range outbounds {
		oMap, ok := o.(map[string]any)
		if !ok {
			newOutbounds = append(newOutbounds, o)
			continue
		}
		if tag, ok := oMap["tag"].(string); ok && tag == vpnGateOutboundTag {
			continue
		}
		newOutbounds = append(newOutbounds, o)
	}
	configMap["outbounds"] = newOutbounds

	newConfigBytes, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return err
	}

	if err := xraySettingService.SaveXraySetting(string(newConfigBytes)); err != nil {
		return err
	}

	return xrayService.RestartXray(true)
}
