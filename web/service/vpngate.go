package service

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
)

type VPNGateService struct{}

const (
	vpnGateAPIURL     = "https://www.vpngate.net/api/iphone/"
	vpnGateCacheTTL   = 5 * time.Minute
	vpnGateMaxServers = 100
)

type VPNGateServer struct {
	HostName          string `json:"hostName"`
	IP                string `json:"ip"`
	CountryLong       string `json:"countryLong"`
	CountryShort      string `json:"countryShort"`
	CountryShortLower string `json:"countryShortLower"`
	NumSessions       int64  `json:"numSessions"`
	ISP               string `json:"isp"`
	ASN               string `json:"asn"`
	IPType            string `json:"ipType"`
	LocalPing         int64  `json:"localPing"`
	Proto             string `json:"proto"`
	Port              string `json:"port"`
	OpenVPNConfig     string `json:"openVPNConfig"`
}

type vpnGateIPResponse struct {
	Status  string `json:"status"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
	Hosting bool   `json:"hosting"`
	Mobile  bool   `json:"mobile"`
	Query   string `json:"query"`
}

type vpnGateIPInfo struct {
	ISP    string
	ASN    string
	IPType string
}

type vpnGateCheckResult struct {
	index     int
	localPing int64
	isAlive   bool
}

var vpnGateMSRegex = regexp.MustCompile(`[=<]\s*(\d+)ms|time[=<]\s*(\d+)\.?(\d*)\s*ms`)

var vpnGateCache struct {
	sync.Mutex
	servers []VPNGateServer
	expires time.Time
}

func (s *VPNGateService) ListServers(refresh bool) ([]VPNGateServer, error) {
	vpnGateCache.Lock()
	defer vpnGateCache.Unlock()

	if !refresh && time.Now().Before(vpnGateCache.expires) {
		return cloneVPNGateServers(vpnGateCache.servers), nil
	}

	servers, err := loadVPNGateServers()
	if err != nil {
		return nil, err
	}
	vpnGateCache.servers = limitVPNGateServers(servers, vpnGateMaxServers)
	vpnGateCache.expires = time.Now().Add(vpnGateCacheTTL)

	lastFetchTimeMutex.Lock()
	lastFetchTime = time.Now()
	lastFetchTimeMutex.Unlock()

	return cloneVPNGateServers(vpnGateCache.servers), nil
}

func loadVPNGateServers() ([]VPNGateServer, error) {
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Get(vpnGateAPIURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("VPNGate request failed: %s", resp.Status)
	}

	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}

	servers, err := parseVPNGateCSV(buf.String())
	if err != nil {
		return nil, err
	}

	ips := make([]string, 0, len(servers))
	for _, server := range servers {
		ips = append(ips, server.IP)
	}
	ipInfo := fetchVPNGateIPData(ips)
	for i := range servers {
		info, ok := ipInfo[servers[i].IP]
		if !ok {
			servers[i].ISP = "Unknown"
			servers[i].ASN = "Unknown"
			servers[i].IPType = "Unknown"
			continue
		}
		servers[i].ISP = info.ISP
		servers[i].ASN = info.ASN
		servers[i].IPType = info.IPType
	}

	servers = checkVPNGateServers(servers)
	sort.Slice(servers, func(i, j int) bool {
		pi, pj := servers[i].LocalPing, servers[j].LocalPing
		if pi == -1 && pj == -1 {
			return servers[i].NumSessions > servers[j].NumSessions
		}
		if pi == -1 {
			return false
		}
		if pj == -1 {
			return true
		}
		if pi != pj {
			return pi < pj
		}
		return servers[i].NumSessions > servers[j].NumSessions
	})

	return servers, nil
}

func cloneVPNGateServers(servers []VPNGateServer) []VPNGateServer {
	clone := make([]VPNGateServer, len(servers))
	copy(clone, servers)
	return clone
}

func limitVPNGateServers(servers []VPNGateServer, limit int) []VPNGateServer {
	if limit <= 0 || len(servers) <= limit {
		return servers
	}
	return servers[:limit]
}

func parseVPNGateCSV(body string) ([]VPNGateServer, error) {
	start := strings.Index(body, "#HostName")
	if start < 0 {
		return nil, errors.New("VPNGate CSV header not found")
	}
	csvData := body[start:]
	if end := strings.LastIndex(csvData, "*"); end >= 0 {
		csvData = csvData[:end]
	}

	reader := csv.NewReader(strings.NewReader(csvData))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, errors.New("VPNGate returned no servers")
	}

	headers := records[0]
	if len(headers) > 0 {
		headers[0] = strings.TrimPrefix(headers[0], "#")
	}
	col := map[string]int{}
	for i, h := range headers {
		col[h] = i
	}
	get := func(row []string, key string) string {
		i, ok := col[key]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	getInt := func(row []string, key string) int64 {
		n, _ := strconv.ParseInt(get(row, key), 10, 64)
		return n
	}

	servers := make([]VPNGateServer, 0, len(records)-1)
	for _, row := range records[1:] {
		if len(row) < len(headers)/2 {
			continue
		}
		config := get(row, "OpenVPN_ConfigData_Base64")
		proto, port := parseVPNGateProtoPort(config)
		ip := get(row, "IP")
		if ip == "" {
			continue
		}
		countryShort := get(row, "CountryShort")
		servers = append(servers, VPNGateServer{
			HostName:          get(row, "HostName"),
			IP:                ip,
			CountryLong:       get(row, "CountryLong"),
			CountryShort:      countryShort,
			CountryShortLower: strings.ToLower(countryShort),
			NumSessions:       getInt(row, "NumVpnSessions"),
			Proto:             proto,
			Port:              port,
			OpenVPNConfig:     config,
		})
	}
	return servers, nil
}

func parseVPNGateProtoPort(base64Config string) (string, string) {
	decoded, err := base64.StdEncoding.DecodeString(base64Config)
	if err != nil {
		return "udp", ""
	}
	proto, port := "udp", ""
	for _, line := range strings.Split(string(decoded), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "remote" {
			port = fields[2]
			if len(fields) >= 4 && strings.Contains(strings.ToLower(fields[3]), "tcp") {
				proto = "tcp"
			}
		}
		if len(fields) >= 2 && fields[0] == "proto" {
			if strings.Contains(strings.ToLower(fields[1]), "tcp") {
				proto = "tcp"
			} else {
				proto = "udp"
			}
		}
	}
	return proto, port
}

func fetchVPNGateIPData(ips []string) map[string]vpnGateIPInfo {
	result := map[string]vpnGateIPInfo{}
	client := &http.Client{Timeout: 15 * time.Second}
	for i := 0; i < len(ips); i += 100 {
		end := i + 100
		if end > len(ips) {
			end = len(ips)
		}
		payload, _ := json.Marshal(ips[i:end])
		resp, err := client.Post("http://ip-api.com/batch?fields=status,isp,org,as,hosting,mobile,query", "application/json", bytes.NewReader(payload))
		if err != nil {
			continue
		}
		var rows []vpnGateIPResponse
		err = json.NewDecoder(resp.Body).Decode(&rows)
		resp.Body.Close()
		if err != nil {
			continue
		}
		for _, row := range rows {
			if row.Status != "success" {
				continue
			}
			isp := row.ISP
			if isp == "" {
				isp = row.Org
			}
			if isp == "" {
				isp = "Unknown"
			}
			result[row.Query] = vpnGateIPInfo{
				ISP:    isp,
				ASN:    extractVPNGateASN(row.AS),
				IPType: determineVPNGateIPType(row.Hosting, row.ISP, row.Org),
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return result
}

func checkVPNGateServers(servers []VPNGateServer) []VPNGateServer {
	tasks := make(chan int, len(servers))
	results := make(chan vpnGateCheckResult, len(servers))
	workers := 30
	if len(servers) < workers {
		workers = len(servers)
	}
	for i := 0; i < workers; i++ {
		go func() {
			for index := range tasks {
				server := servers[index]
				ping := pingVPNGateIP(server.IP)
				alive := ping >= 0
				if server.Proto == "tcp" && server.Port != "" {
					alive = testVPNGateTCP(server.IP, server.Port)
				}
				results <- vpnGateCheckResult{index: index, localPing: ping, isAlive: alive}
			}
		}()
	}
	for i := range servers {
		tasks <- i
	}
	close(tasks)

	checked := make([]vpnGateCheckResult, len(servers))
	for range servers {
		res := <-results
		checked[res.index] = res
	}
	active := make([]VPNGateServer, 0, len(servers))
	for i, res := range checked {
		if res.isAlive {
			servers[i].LocalPing = res.localPing
			active = append(active, servers[i])
		}
	}
	return active
}

func testVPNGateTCP(ip, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func pingVPNGateIP(ip string) int64 {
	args := []string{"-c", "1", "-W", "1", ip}
	if runtime.GOOS == "windows" {
		args = []string{"-n", "1", "-w", "1000", ip}
	}
	cmd := exec.Command("ping", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return -1
	}
	matches := vpnGateMSRegex.FindStringSubmatch(out.String())
	for _, match := range matches[1:] {
		if match == "" {
			continue
		}
		n, err := strconv.ParseInt(match, 10, 64)
		if err == nil {
			return n
		}
	}
	return -1
}

func extractVPNGateASN(as string) string {
	if as == "" {
		return "Unknown"
	}
	parts := strings.Fields(as)
	if len(parts) > 0 && strings.HasPrefix(strings.ToUpper(parts[0]), "AS") {
		return parts[0]
	}
	return as
}

func determineVPNGateIPType(hosting bool, isp, org string) string {
	if hosting {
		return "机房IP"
	}
	text := strings.ToLower(isp + " " + org)
	for _, keyword := range []string{"datacenter", "hosting", "cloud", "vps", "amazon", "aws", "google", "microsoft", "azure", "oracle", "linode", "ovh", "vultr", "hetzner", "contabo", "tencent", "alibaba"} {
		if strings.Contains(text, keyword) {
			return "机房IP"
		}
	}
	return "住宅IP"
}

var (
	lastFetchTime      time.Time
	lastFetchTimeMutex sync.Mutex
)

func CheckAndRefreshVPNGate(intervalMinutes int) {
	lastFetchTimeMutex.Lock()
	defer lastFetchTimeMutex.Unlock()

	// Initial load if lastFetchTime is zero
	if lastFetchTime.IsZero() || time.Since(lastFetchTime) >= time.Duration(intervalMinutes)*time.Minute {
		lastFetchTime = time.Now() // Set immediately to prevent duplicate runs
		// Fetch in the background so we do not block the cron scheduler
		go func() {
			logger.Info("[VPNGate] Background periodic node fetching started...")
			vpngateService := &VPNGateService{}
			_, err := vpngateService.ListServers(true) // force refresh and cache
			if err != nil {
				logger.Errorf("[VPNGate] Background periodic node fetch failed: %v", err)
				lastFetchTimeMutex.Lock()
				lastFetchTime = time.Time{} // reset on failure to retry on next check
				lastFetchTimeMutex.Unlock()
			} else {
				logger.Info("[VPNGate] Background periodic node fetch completed successfully.")
			}
		}()
	}
}

func (s *VPNGateService) ClearCache() {
	vpnGateCache.Lock()
	defer vpnGateCache.Unlock()
	vpnGateCache.servers = nil
	vpnGateCache.expires = time.Time{}
}
