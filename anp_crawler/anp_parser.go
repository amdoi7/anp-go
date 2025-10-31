package anp_crawler

import (
	"context"
	"fmt"
	"strings"

	"github.com/bytedance/sonic"
)

// Parser parses raw ANP documents into structured data.
type Parser interface {
	Parse(ctx context.Context, content []byte, contentType, sourceURL string) (*ParseResult, error)
}

// ParseResult holds extracted interfaces and agent metadata.
type ParseResult struct {
	Interfaces []InterfaceEntry
	Agents     []AgentEntry
}

// InterfaceEntry captures the metadata for a single interface definition.
type InterfaceEntry struct {
	Type          string   `json:"type"`
	Protocol      string   `json:"protocol"`
	MethodName    string   `json:"method_name,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	Description   string   `json:"description,omitempty"`
	Params        []byte   `json:"params,omitempty"`
	Result        []byte   `json:"result,omitempty"`
	Components    []byte   `json:"components,omitempty"`
	Content       []byte   `json:"content,omitempty"`
	Servers       []Server `json:"servers,omitempty"`
	ParentServers []Server `json:"parent_servers,omitempty"`
	Source        string   `json:"source"`
	URL           string   `json:"url,omitempty"`
}

// AgentEntry describes an agent in an agent directory document.
type AgentEntry struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	URL         string  `json:"url"`
	Rating      float64 `json:"rating"`
	UsageCount  int64   `json:"usage_count"`
	ReviewCount int64   `json:"review_count"`
}

// Server describes an OpenRPC server entry.
type Server struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

// JSONParser is the default parser that understands JSON Agent Description documents.
type JSONParser struct{}

// NewJSONParser constructs a JSONParser.
func NewJSONParser() Parser {
	return &JSONParser{}
}

// Parse implements the Parser interface.
func (p *JSONParser) Parse(_ context.Context, content []byte, contentType, sourceURL string) (*ParseResult, error) {
	if !strings.Contains(strings.ToLower(contentType), "json") && contentType != "" {
		logger.Debug("content type not recognised as JSON", "content_type", contentType)
	}

	var data map[string]any
	if err := sonic.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("parse JSON content from %s: %w", sourceURL, err)
	}

	result := &ParseResult{}

	if isOpenRPC(data) {
		result.Interfaces = append(result.Interfaces, extractOpenRPCInterfaces(data)...)
		return result, nil
	}

	if agents := extractAgentList(data); len(agents) > 0 {
		result.Agents = agents
	}

	if isAgentDescription(data) {
		result.Interfaces = append(result.Interfaces, extractInterfacesFromAgentDescription(data)...)
		return result, nil
	}

	if isJSONRPC(data) {
		if iface, err := extractJSONRPCInterface(data); err == nil {
			result.Interfaces = append(result.Interfaces, iface)
		} else {
			return nil, fmt.Errorf("extract JSON-RPC interface from %s: %w", sourceURL, err)
		}
		return result, nil
	}

	logger.Debug("unsupported document structure", "source", sourceURL)
	return result, nil
}

func isOpenRPC(data map[string]any) bool {
	_, hasOpenRPC := data["openrpc"]
	methods, hasMethods := data["methods"]
	return hasOpenRPC && hasMethods && methods != nil
}

func isAgentDescription(data map[string]any) bool {
	_, hasInterfaces := data["interfaces"]
	return hasInterfaces
}

func isJSONRPC(data map[string]any) bool {
	_, hasJSONRPC := data["jsonrpc"]
	_, hasMethod := data["method"]
	_, hasID := data["id"]
	_, hasMethodsArray := data["methods"]
	return hasJSONRPC || (hasMethod && hasID) || hasMethodsArray
}

func extractOpenRPCInterfaces(data map[string]any) []InterfaceEntry {
	methodsRaw, ok := data["methods"]
	if !ok || methodsRaw == nil {
		return nil
	}

	methods, ok := methodsRaw.([]any)
	if !ok {
		logger.Debug("OpenRPC methods field is not an array")
		return nil
	}

	components, _ := sonic.Marshal(data["components"])

	var servers []Server
	if serversRaw, ok := data["servers"]; ok && serversRaw != nil {
		serversJSON, _ := sonic.Marshal(serversRaw)
		sonic.Unmarshal(serversJSON, &servers)
	}

	interfaces := make([]InterfaceEntry, 0, len(methods))
	for _, method := range methods {
		methodMap, ok := method.(map[string]any)
		if !ok {
			continue
		}

		params, _ := sonic.Marshal(methodMap["params"])
		result, _ := sonic.Marshal(methodMap["result"])

		interfaces = append(interfaces, InterfaceEntry{
			Type:        "openrpc_method",
			Protocol:    "openrpc",
			MethodName:  getString(methodMap, "name"),
			Summary:     getString(methodMap, "summary"),
			Description: getString(methodMap, "description"),
			Params:      params,
			Result:      result,
			Components:  components,
			Servers:     servers,
			Source:      "openrpc_interface",
		})
	}

	return interfaces
}

func extractInterfacesFromAgentDescription(data map[string]any) []InterfaceEntry {
	interfacesListRaw, ok := data["interfaces"]
	if !ok || interfacesListRaw == nil {
		return nil
	}

	interfacesList, ok := interfacesListRaw.([]any)
	if !ok {
		logger.Debug("AgentDescription interfaces field is not an array")
		return nil
	}

	var globalServers []Server
	if globalServersRaw, ok := data["servers"]; ok && globalServersRaw != nil {
		serversJSON, _ := sonic.Marshal(globalServersRaw)
		sonic.Unmarshal(serversJSON, &globalServers)
	}

	var interfaces []InterfaceEntry
	for _, ifaceDef := range interfacesList {
		ifaceMap, ok := ifaceDef.(map[string]any)
		if !ok {
			continue
		}

		ifaceType := getString(ifaceMap, "type")
		ifaceProtocol := getString(ifaceMap, "protocol")

		if strings.EqualFold(ifaceType, "StructuredInterface") && strings.EqualFold(ifaceProtocol, "openrpc") && ifaceMap["content"] != nil {
			content, ok := ifaceMap["content"].(map[string]any)
			if !ok || !isOpenRPC(content) {
				logger.Debug("invalid OpenRPC content in StructuredInterface")
				continue
			}
			embedded := extractOpenRPCInterfaces(content)
			for idx := range embedded {
				if len(embedded[idx].Servers) == 0 {
					embedded[idx].ParentServers = globalServers
				}
			}
			interfaces = append(interfaces, embedded...)
			continue
		}

		var inlineContent []byte
		if rawContent, ok := ifaceMap["content"]; ok {
			inlineContent, _ = sonic.Marshal(rawContent)
		}

		interfaces = append(interfaces, InterfaceEntry{
			Type:          ifaceType,
			Protocol:      ifaceProtocol,
			URL:           getString(ifaceMap, "url"),
			Description:   getString(ifaceMap, "description"),
			Source:        "agent_description",
			ParentServers: globalServers,
			Content:       inlineContent,
		})
	}

	return interfaces
}

func extractJSONRPCInterface(data map[string]any) (InterfaceEntry, error) {
	methodName := getString(data, "method")
	if methodName == "" {
		methodName = getString(data, "name")
	}
	if methodName == "" {
		return InterfaceEntry{}, fmt.Errorf("JSON-RPC method name not found")
	}

	params, _ := sonic.Marshal(data["params"])
	result, _ := sonic.Marshal(data["returns"])

	return InterfaceEntry{
		Type:        "jsonrpc_method",
		Protocol:    "JSON-RPC 2.0",
		MethodName:  methodName,
		Description: getString(data, "description"),
		Params:      params,
		Result:      result,
		Source:      "jsonrpc_interface",
	}, nil
}

func extractAgentList(data map[string]any) []AgentEntry {
	rawAgents, ok := data["agentList"].([]any)
	if !ok {
		return nil
	}

	entries := make([]AgentEntry, 0, len(rawAgents))
	for _, item := range rawAgents {
		agentMap, ok := item.(map[string]any)
		if !ok {
			continue
		}

		entry := AgentEntry{
			Name:        getString(agentMap, "name"),
			Description: getString(agentMap, "description"),
			URL:         getString(agentMap, "url"),
			Rating:      getFloat(agentMap, "rating"),
			UsageCount:  getInt(agentMap, "usage_count"),
			ReviewCount: getInt(agentMap, "review_count"),
		}
		entries = append(entries, entry)
	}

	return entries
}

func getString(data map[string]any, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}

func getFloat(data map[string]any, key string) float64 {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case float32:
			return float64(v)
		case int:
			return float64(v)
		case int64:
			return float64(v)
		default:
			logger.Debug("unexpected type for key", "key", key, "type", fmt.Sprintf("%T", v))
		}
	}
	return 0
}

func getInt(data map[string]any, key string) int64 {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case float64:
			return int64(v)
		case float32:
			return int64(v)
		case int:
			return int64(v)
		case int64:
			return v
		default:
			logger.Debug("unexpected type for key", "key", key, "type", fmt.Sprintf("%T", v))
		}
	}
	return 0
}
