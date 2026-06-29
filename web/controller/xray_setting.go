package controller

import (
	"encoding/json"
	"strconv"

	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
)

// XraySettingController handles Xray configuration and settings operations.
type XraySettingController struct {
	XraySettingService service.XraySettingService
	SettingService     service.SettingService
	InboundService     service.InboundService
	OutboundService    service.OutboundService
	XrayService        service.XrayService
	WarpService        service.WarpService
	VPNGateService     service.VPNGateService
	OpenVPNService     service.OpenVPNService
}

// NewXraySettingController creates a new XraySettingController and initializes its routes.
func NewXraySettingController(g *gin.RouterGroup) *XraySettingController {
	a := &XraySettingController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the routes for Xray settings management.
func (a *XraySettingController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/xray")
	g.GET("/getDefaultJsonConfig", a.getDefaultXrayConfig)
	g.GET("/getOutboundsTraffic", a.getOutboundsTraffic)
	g.GET("/getXrayResult", a.getXrayResult)

	g.POST("/", a.getXraySetting)
	g.POST("/warp/:action", a.warp)
	g.POST("/vpngate/list", a.vpngateList)
	g.POST("/vpngate/:action", a.vpngate)
	g.POST("/update", a.updateSetting)
	g.POST("/resetOutboundsTraffic", a.resetOutboundsTraffic)
	g.POST("/testOutbound", a.testOutbound)
}

// getXraySetting retrieves the Xray configuration template, inbound tags, and outbound test URL.
func (a *XraySettingController) getXraySetting(c *gin.Context) {
	xraySetting, err := a.SettingService.GetXrayConfigTemplate()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	// Older versions of this handler embedded the raw DB value as
	// `xraySetting` in the response without checking if the value
	// already had that wrapper shape. When the frontend saved it
	// back through the textarea verbatim, the wrapper got persisted
	// and every subsequent save nested another layer, which is what
	// eventually produced the blank Xray Settings page in #4059.
	// Strip any such wrapper here, and heal the DB if we found one so
	// the next read is O(1) instead of climbing the same pile again.
	if unwrapped := service.UnwrapXrayTemplateConfig(xraySetting); unwrapped != xraySetting {
		if saveErr := a.XraySettingService.SaveXraySetting(unwrapped); saveErr == nil {
			xraySetting = unwrapped
		} else {
			// Don't fail the read — just serve the unwrapped value
			// and leave the DB healing for a later save.
			xraySetting = unwrapped
		}
	}
	inboundTags, err := a.InboundService.GetInboundTags()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	clientReverseTags, err := a.InboundService.GetClientReverseTags()
	if err != nil {
		clientReverseTags = "[]"
	}
	outboundTestUrl, _ := a.SettingService.GetXrayOutboundTestUrl()
	if outboundTestUrl == "" {
		outboundTestUrl = "https://www.google.com/generate_204"
	}
	xrayResponse := map[string]any{
		"xraySetting":       json.RawMessage(xraySetting),
		"inboundTags":       json.RawMessage(inboundTags),
		"clientReverseTags": json.RawMessage(clientReverseTags),
		"outboundTestUrl":   outboundTestUrl,
	}
	result, err := json.Marshal(xrayResponse)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, string(result), nil)
}

// updateSetting updates the Xray configuration settings.
func (a *XraySettingController) updateSetting(c *gin.Context) {
	xraySetting := c.PostForm("xraySetting")
	if err := a.XraySettingService.SaveXraySetting(xraySetting); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	outboundTestUrl := c.PostForm("outboundTestUrl")
	if outboundTestUrl == "" {
		outboundTestUrl = "https://www.google.com/generate_204"
	}
	_ = a.SettingService.SetXrayOutboundTestUrl(outboundTestUrl)
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), nil)
}

// getDefaultXrayConfig retrieves the default Xray configuration.
func (a *XraySettingController) getDefaultXrayConfig(c *gin.Context) {
	defaultJsonConfig, err := a.SettingService.GetDefaultXrayConfig()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, defaultJsonConfig, nil)
}

// getXrayResult retrieves the current Xray service result.
func (a *XraySettingController) getXrayResult(c *gin.Context) {
	jsonObj(c, a.XrayService.GetXrayResult(), nil)
}

// warp handles Cloudflare WARP account and outbound setup.
func (a *XraySettingController) warp(c *gin.Context) {
	action := c.Param("action")
	var resp string
	var err error

	switch action {
	case "data":
		resp, err = a.WarpService.GetWarpData()
	case "del":
		err = a.WarpService.DelWarpData()
	case "config":
		resp, err = a.WarpService.GetWarpConfig()
	case "reg":
		resp, err = a.WarpService.RegWarp(c.PostForm("privateKey"), c.PostForm("publicKey"))
	case "license":
		resp, err = a.WarpService.SetWarpLicense(c.PostForm("license"))
	default:
		err = common.NewError("unknown warp action")
	}

	jsonObj(c, resp, err)
}

func (a *XraySettingController) vpngateList(c *gin.Context) {
	servers, err := a.VPNGateService.ListServers(c.PostForm("refresh") == "true")
	jsonObj(c, servers, err)
}

func (a *XraySettingController) vpngate(c *gin.Context) {
	action := c.Param("action")
	var resp any
	var err error

	switch action {
	case "start":
		var server service.VPNGateServer
		err = json.Unmarshal([]byte(c.PostForm("server")), &server)
		if err == nil {
			ruleMode := c.PostForm("ruleMode")
			var selectedCountries []string
			_ = json.Unmarshal([]byte(c.PostForm("selectedCountries")), &selectedCountries)
			fallbackEnable := c.PostForm("fallbackEnable") == "true"
			resp, err = a.OpenVPNService.StartVPNGate(server, ruleMode, selectedCountries, fallbackEnable)
		}
	case "get_settings":
		interval, errVal := a.SettingService.GetVPNGateRefreshInterval()
		if errVal != nil {
			interval = 120
		}
		favStr, errVal := a.SettingService.GetVPNGateFavorites()
		if errVal != nil {
			favStr = "[]"
		}
		var favorites []string
		_ = json.Unmarshal([]byte(favStr), &favorites)
		resp = map[string]any{
			"favorites":       favorites,
			"refreshInterval": interval,
		}
	case "save_settings":
		intervalStr := c.PostForm("refreshInterval")
		interval, errVal := strconv.Atoi(intervalStr)
		if errVal != nil || interval < 15 || interval > 4320 {
			interval = 120
		}
		favoritesStr := c.PostForm("favorites")
		var favorites []string
		if errVal := json.Unmarshal([]byte(favoritesStr), &favorites); errVal != nil {
			favoritesStr = "[]"
		}
		err = a.SettingService.SetVPNGateRefreshInterval(interval)
		if err == nil {
			err = a.SettingService.SetVPNGateFavorites(favoritesStr)
		}
		resp = map[string]any{"success": err == nil}
	case "status":
		status := a.OpenVPNService.VPNGateStatus()
		resp = &status
	case "cancel":
		status := a.OpenVPNService.CancelVPNGate()
		resp = &status
	case "stop":
		status := a.OpenVPNService.StopVPNGate()
		resp = &status
	case "uninstall":
		err = a.OpenVPNService.UninstallVPNGate()
		status := a.OpenVPNService.VPNGateStatus()
		resp = &status
	default:
		err = common.NewError("unknown vpngate action")
	}

	jsonObj(c, resp, err)
}

// getOutboundsTraffic retrieves the traffic statistics for outbounds.
func (a *XraySettingController) getOutboundsTraffic(c *gin.Context) {
	outboundsTraffic, err := a.OutboundService.GetOutboundsTraffic()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getOutboundTrafficError"), err)
		return
	}
	jsonObj(c, outboundsTraffic, nil)
}

// resetOutboundsTraffic resets the traffic statistics for the specified outbound tag.
func (a *XraySettingController) resetOutboundsTraffic(c *gin.Context) {
	tag := c.PostForm("tag")
	err := a.OutboundService.ResetOutboundTraffic(tag)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.resetOutboundTrafficError"), err)
		return
	}
	jsonObj(c, "", nil)
}

// testOutbound tests an outbound configuration and returns the delay/response time.
// Optional form "allOutbounds": JSON array of all outbounds; used to resolve sockopt.dialerProxy dependencies.
func (a *XraySettingController) testOutbound(c *gin.Context) {
	outboundJSON := c.PostForm("outbound")
	allOutboundsJSON := c.PostForm("allOutbounds")

	if outboundJSON == "" {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), common.NewError("outbound parameter is required"))
		return
	}

	// Load the test URL from server settings to prevent SSRF via user-controlled URLs
	testURL, _ := a.SettingService.GetXrayOutboundTestUrl()

	result, err := a.OutboundService.TestOutbound(outboundJSON, testURL, allOutboundsJSON)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	jsonObj(c, result, nil)
}
