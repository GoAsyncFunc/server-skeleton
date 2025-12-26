package service

import (
	"encoding/json"
	"fmt"
	"strconv"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// InboundBuilder builds Inbound config.
// IMPORTANT: This skeleton implementation defaults to TROJAN.
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo) (*core.InboundHandlerConfig, error) {
	// Trojan config from uniproxy NodeInfo
	// Note: uniproxy NodeInfo contains *TrojanNode
	if nodeInfo.Trojan == nil {
		// Fallback or error if we expect Trojan
		return nil, fmt.Errorf("node info missing Trojan config")
	}
	trojanInfo := nodeInfo.Trojan

	var (
		streamSetting     *conf.StreamConfig
		transportProtocol conf.TransportProtocol
	)

	inboundDetourConfig := &conf.InboundDetourConfig{}

	// Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: uint32(trojanInfo.ServerPort), To: uint32(trojanInfo.ServerPort)}},
	}
	inboundDetourConfig.PortList = portList

	// Tag
	inboundDetourConfig.Tag = fmt.Sprintf("trojan_%d", trojanInfo.ServerPort)

	// Sniffing
	sniffingConfig := &conf.SniffingConfig{
		Enabled: false,
	}
	if trojanInfo.BaseConfig != nil {
		// uniproxy model might differ slightly, checking inspection again if needed.
		// For now assume defaults or simple logic.
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	// Protocol
	inboundDetourConfig.Protocol = "trojan"
	// conf.JSON is not exported or doesn't exist in recent xray-core conf package as a type we can cast to directly for Settings?
	// Actually, settings in `conf` struct are usually `*json.RawMessage`.
	// Let's check the definition of InboundDetourConfig.Settings.
	// It is usually `*json.RawMessage`.

	// Stream Settings
	streamSetting = new(conf.StreamConfig)
	inboundDetourConfig.StreamSetting = streamSetting

	// Network
	transportProtocol = conf.TransportProtocol(trojanInfo.Network)
	if transportProtocol == "tcp" {
		if len(trojanInfo.NetworkSettings) > 0 {
			// Try parsing if specific settings exist
			tcpConfig := new(conf.TCPConfig)
			if err := json.Unmarshal(trojanInfo.NetworkSettings, tcpConfig); err == nil {
				streamSetting.TCPSettings = tcpConfig
			}
		}
	} else if transportProtocol == "grpc" {
		if len(trojanInfo.NetworkSettings) > 0 {
			grpcConfig := new(conf.GRPCConfig)
			if err := json.Unmarshal(trojanInfo.NetworkSettings, grpcConfig); err != nil {
				return nil, fmt.Errorf("unmarshal grpc config error: %w", err)
			}
			streamSetting.GRPCSettings = grpcConfig
		} else {
			streamSetting.GRPCSettings = &conf.GRPCConfig{}
		}
	} else if transportProtocol == "ws" {
		if len(trojanInfo.NetworkSettings) > 0 {
			wsConfig := new(conf.WebSocketConfig)
			if err := json.Unmarshal(trojanInfo.NetworkSettings, wsConfig); err != nil {
				return nil, fmt.Errorf("unmarshal ws config error: %w", err)
			}
			streamSetting.WSSettings = wsConfig
		}
	}

	// TLS
	tlsSettings := new(conf.TLSConfig) // conf.TLSConfig uses Certs []*conf.TLSCertConfig (based on debug output)
	if nodeInfo.Security == 1 {        // TLS
		streamSetting.Security = "tls"
		tlsSettings.Certs = []*conf.TLSCertConfig{
			{
				CertFile: config.Cert.CertFile,
				KeyFile:  config.Cert.KeyFile,
			},
		}
		streamSetting.TLSSettings = tlsSettings
	} else if nodeInfo.Security == 2 { // REALITY
		streamSetting.Security = "reality"
		// Reality logic...
	}

	// Set network
	streamSetting.Network = &transportProtocol

	// Users - Handled by service.AddUser dynamically usually, but for init we can add if logic allows
	// In Main builder it will add users. Here we just set up the handler skeleton.
	// However, Xray usually needs at least one user or Fallback?
	// Trojan protocol settings:
	clients := []json.RawMessage{}
	// We leave clients empty here as Builder.Start will populate them using UserManager

	// Construct generic Trojan settings
	// Since we are using conf.JSON for settings which is raw bytes, we need to construct it properly
	// or use a helper struct to marshal.
	type Fallback struct {
		Alpn string          `json:"alpn,omitempty"`
		Path string          `json:"path,omitempty"`
		Dest json.RawMessage `json:"dest"`
		Xver int             `json:"xver,omitempty"`
	}
	type TrojanSettings struct {
		Clients   []json.RawMessage `json:"clients"`
		Fallbacks []*Fallback       `json:"fallbacks,omitempty"`
	}
	settings := TrojanSettings{
		Clients: clients,
	}
	settingsBytes, _ := json.Marshal(settings)
	settingsJSON := json.RawMessage(settingsBytes)
	inboundDetourConfig.Settings = &settingsJSON

	return inboundDetourConfig.Build()
}

func stringSliceToPortList(s []string) *conf.PortList {
	var portList conf.PortList
	for _, p := range s {
		port, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		portList.Range = append(portList.Range, conf.PortRange{From: uint32(port), To: uint32(port)})
	}
	return &portList
}
