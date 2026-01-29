package service

import (
	"encoding/json"
	"fmt"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// InboundBuilder builds Inbound config.
// IMPORTANT: This skeleton implementation defaults to TROJAN.
// InboundBuilder builds Inbound config.
// IMPORTANT: This is an EXAMPLE implementation using TROJAN.
// Developers MUST replace this entire function body with the logic for their specific protocol.
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo) (*core.InboundHandlerConfig, error) {
	// =================================================================================
	// [EXAMPLE START] Trojan Protocol Implementation
	// Replace the code below with your protocol-specific logic.
	// =================================================================================

	// 1. Validate Node Config
	// Note: uniproxy NodeInfo contains protocol-specific fields (e.g., Trojan, Vmess, Vless).
	// Ensure you check the correct field for your protocol.
	if nodeInfo.Trojan == nil {
		return nil, fmt.Errorf("node info missing Trojan config")
	}
	trojanInfo := nodeInfo.Trojan

	var (
		streamSetting     *conf.StreamConfig
		transportProtocol conf.TransportProtocol
	)

	inboundDetourConfig := &conf.InboundDetourConfig{}

	// 2. Configure Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: uint32(trojanInfo.ServerPort), To: uint32(trojanInfo.ServerPort)}},
	}
	inboundDetourConfig.PortList = portList

	// 3. Configure Tag (Unique identifier for this inbound)
	inboundDetourConfig.Tag = fmt.Sprintf("trojan_%d", trojanInfo.ServerPort)

	// 4. Configure Sniffing (Optional)
	sniffingConfig := &conf.SniffingConfig{
		Enabled: false,
	}
	// Add sniffing logic here if needed...
	inboundDetourConfig.SniffingConfig = sniffingConfig

	// 5. Configure Protocol
	inboundDetourConfig.Protocol = "trojan"

	// 6. Configure Stream Settings (TCP, WebSocket, gRPC, etc.)
	streamSetting = new(conf.StreamConfig)
	inboundDetourConfig.StreamSetting = streamSetting

	transportProtocol = conf.TransportProtocol(trojanInfo.Network)
	streamSetting.Network = &transportProtocol

	switch transportProtocol {
	case "tcp":
		if len(trojanInfo.NetworkSettings) > 0 {
			tcpConfig := new(conf.TCPConfig)
			if err := json.Unmarshal(trojanInfo.NetworkSettings, tcpConfig); err == nil {
				streamSetting.TCPSettings = tcpConfig
			}
		}
	case "grpc":
		if len(trojanInfo.NetworkSettings) > 0 {
			grpcConfig := new(conf.GRPCConfig)
			if err := json.Unmarshal(trojanInfo.NetworkSettings, grpcConfig); err != nil {
				return nil, fmt.Errorf("unmarshal grpc config error: %w", err)
			}
			streamSetting.GRPCSettings = grpcConfig
		} else {
			streamSetting.GRPCSettings = &conf.GRPCConfig{}
		}
	case "ws":
		if len(trojanInfo.NetworkSettings) > 0 {
			wsConfig := new(conf.WebSocketConfig)
			if err := json.Unmarshal(trojanInfo.NetworkSettings, wsConfig); err != nil {
				return nil, fmt.Errorf("unmarshal ws config error: %w", err)
			}
			streamSetting.WSSettings = wsConfig
		}
	}

	// 7. Configure Security (TLS, Reality, etc.)
	tlsSettings := new(conf.TLSConfig)
	switch nodeInfo.Security {
	case 1: // TLS
		streamSetting.Security = "tls"
		tlsSettings.Certs = []*conf.TLSCertConfig{
			{
				CertFile: config.Cert.CertFile,
				KeyFile:  config.Cert.KeyFile,
			},
		}
		streamSetting.TLSSettings = tlsSettings
	case 2: // REALITY
		streamSetting.Security = "reality"
		// Add Reality configuration logic here...
	}

	// 8. Configure Protocol Settings (Clients, Fallbacks, etc.)
	// Xray usually requires at least one user or fallback.
	// Users are typically added dynamically by UserBuilder, but you can set defaults here.
	clients := []json.RawMessage{}

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

	// =================================================================================
	// [EXAMPLE END]
	// =================================================================================

	return inboundDetourConfig.Build()
}
