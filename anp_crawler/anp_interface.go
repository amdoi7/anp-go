package anp_crawler

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
)

// ANPInterface represents a single ANP interface that can execute tool calls.
type ANPInterface struct {
	ToolName string
	Entry    InterfaceEntry
	Client   Client
	Method   string
	Servers  []Server
}

// NewANPInterface creates a new ANPInterface wrapper around an InterfaceEntry.
func NewANPInterface(toolName string, entry InterfaceEntry, client Client) *ANPInterface {
	servers := entry.Servers
	if len(servers) == 0 {
		servers = entry.ParentServers
	}
	return &ANPInterface{
		ToolName: toolName,
		Entry:    entry,
		Client:   client,
		Method:   entry.MethodName,
		Servers:  servers,
	}
}

// Execute executes the interface with the given arguments.
func (i *ANPInterface) Execute(ctx context.Context, arguments map[string]any) (map[string]any, error) {
	if len(i.Servers) == 0 {
		return nil, fmt.Errorf("no servers defined for tool: %s", i.ToolName)
	}

	serverURL := i.Servers[0].URL
	if serverURL == "" {
		return nil, fmt.Errorf("no server URL found for tool: %s", i.ToolName)
	}

	if strings.TrimSpace(i.Method) == "" {
		return nil, fmt.Errorf("no method name found for tool: %s", i.ToolName)
	}

	processedArgs := make(map[string]any)
	for key, value := range arguments {
		if strVal, ok := value.(string); ok {
			if (strings.HasPrefix(strVal, "{") && strings.HasSuffix(strVal, "}")) || (strings.HasPrefix(strVal, "[") && strings.HasSuffix(strVal, "]")) {
				var jsonData any
				if err := sonic.Unmarshal([]byte(strVal), &jsonData); err == nil {
					processedArgs[key] = jsonData
					continue
				}
			}
		}
		processedArgs[key] = value
	}

	rpcRequest := map[string]any{
		"jsonrpc": "2.0",
		"id":      uuid.NewString(),
		"method":  i.Method,
		"params":  processedArgs,
	}

	logger.Debug("executing tool call", "tool", i.ToolName, "method", i.Method, "url", serverURL)

	resp, err := i.Client.Fetch(ctx, "POST", serverURL, map[string]string{"Content-Type": "application/json"}, rpcRequest)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed for tool %s to %s: %w", i.ToolName, serverURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var rpcResponse map[string]any
	if err := sonic.Unmarshal(resp.Body, &rpcResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JSON-RPC response for tool %s from %s: %w", i.ToolName, serverURL, err)
	}

	if errVal, ok := rpcResponse["error"]; ok {
		return nil, fmt.Errorf("JSON-RPC error for tool %s from %s: %v", i.ToolName, serverURL, errVal)
	}

	return rpcResponse, nil
}

// ANPInterfaceConverter converts interface entries to generic tool definitions.
type ANPInterfaceConverter struct{}

// NewANPInterfaceConverter creates a new ANPInterfaceConverter.
func NewANPInterfaceConverter() *ANPInterfaceConverter {
	return &ANPInterfaceConverter{}
}

// ANPTool is the struct for the tool in a generic format.
type ANPTool struct {
	Type     string   `json:"type"`
	Function Function `json:"function"`
}

// Function is the struct for the function in an ANP tool.
type Function struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Parameters  Parameters `json:"parameters"`
}

// Parameters is the struct for the parameters in an ANP tool.
type Parameters struct {
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
	Required   []string       `json:"required"`
}

// ConvertToANPTool converts an InterfaceEntry to a generic tool definition.
func (c *ANPInterfaceConverter) ConvertToANPTool(entry InterfaceEntry) (*ANPTool, error) {
	switch entry.Type {
	case "openrpc_method":
		return c.convertOpenRPCMethod(entry)
	case "jsonrpc_method":
		return c.convertJSONRPCMethod(entry)
	default:
		logger.Debug("skipping unsupported interface type", "type", entry.Type)
		return nil, nil
	}
}

func (c *ANPInterfaceConverter) convertOpenRPCMethod(entry InterfaceEntry) (*ANPTool, error) {
	var paramsArray []map[string]any
	if err := sonic.Unmarshal(entry.Params, &paramsArray); err == nil && len(paramsArray) > 0 {
		properties := make(map[string]any)
		var required []string
		for _, p := range paramsArray {
			name, ok := p["name"].(string)
			if !ok || name == "" {
				continue
			}
			if schema, ok := p["schema"]; ok {
				properties[name] = schema
			}
			if req, ok := p["required"].(bool); ok && req {
				required = append(required, name)
			}
		}
		return c.buildANPTool(entry, Parameters{Type: "object", Properties: properties, Required: required}), nil
	}

	var schema map[string]any
	if err := sonic.Unmarshal(entry.Params, &schema); err != nil {
		return nil, fmt.Errorf("failed to parse openrpc params for method %s: %w", entry.MethodName, err)
	}

	return c.buildANPTool(entry, convertSchemaToParameters(schema)), nil
}

func (c *ANPInterfaceConverter) convertJSONRPCMethod(entry InterfaceEntry) (*ANPTool, error) {
	var params map[string]any
	if err := sonic.Unmarshal(entry.Params, &params); err != nil {
		return nil, fmt.Errorf("failed to parse jsonrpc params for method %s: %w", entry.MethodName, err)
	}

	properties := make(map[string]any)
	var required []string
	for name, p := range params {
		prop, ok := p.(map[string]any)
		if !ok {
			properties[name] = map[string]any{"type": "string"}
			continue
		}
		properties[name] = prop
		if req, ok := prop["required"].(bool); ok && req {
			required = append(required, name)
		}
	}

	return &ANPTool{
		Type: "function",
		Function: Function{
			Name:        sanitizeFunctionName(entry.MethodName),
			Description: entry.Description,
			Parameters: Parameters{
				Type:       "object",
				Properties: properties,
				Required:   required,
			},
		},
	}, nil
}

func (c *ANPInterfaceConverter) buildANPTool(entry InterfaceEntry, params Parameters) *ANPTool {
	description := entry.Description
	if description == "" {
		description = entry.Summary
	}

	return &ANPTool{
		Type: "function",
		Function: Function{
			Name:        sanitizeFunctionName(entry.MethodName),
			Description: description,
			Parameters:  params,
		},
	}
}

func convertSchemaToParameters(schema map[string]any) Parameters {
	paramType := "object"
	if t, ok := schema["type"].(string); ok && t != "" {
		paramType = t
	}

	properties := make(map[string]any)
	if props, ok := schema["properties"].(map[string]any); ok {
		properties = props
	}

	var required []string
	if reqList, ok := schema["required"].([]any); ok {
		for _, item := range reqList {
			if name, ok := item.(string); ok {
				required = append(required, name)
			}
		}
	}

	return Parameters{
		Type:       paramType,
		Properties: properties,
		Required:   required,
	}
}

func sanitizeFunctionName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "unknown_function"
	}
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	sanitized := re.ReplaceAllString(name, "_")
	if len(sanitized) > 64 {
		sanitized = sanitized[:64]
	}
	return sanitized
}
