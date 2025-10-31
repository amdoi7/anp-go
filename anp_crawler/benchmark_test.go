package anp_crawler

import (
	"context"
	"testing"
)

const benchmarkOpenRPCDoc = `{
  "openrpc": "1.2.6",
  "info": {"title": "Benchmark", "version": "1.0.0"},
  "methods": [
    {
      "name": "demo_method",
      "summary": "Demo method",
      "description": "Returns a greeting",
      "params": [
        {
          "name": "name",
          "required": true,
          "schema": {"type": "string"}
        }
      ],
      "result": {
        "name": "result",
        "schema": {
          "type": "object",
          "properties": {"message": {"type": "string"}}
        }
      }
    }
  ],
  "servers": [{"name": "demo", "url": "https://example.com/rpc"}]
}`

func BenchmarkParseAndConvert(b *testing.B) {
	parser := NewJSONParser()
	converter := NewANPInterfaceConverter()
	ctx := context.Background()
	content := []byte(benchmarkOpenRPCDoc)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result, err := parser.Parse(ctx, content, "application/json", "https://example.com/openrpc.json")
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
		for _, entry := range result.Interfaces {
			if _, err := converter.ConvertToANPTool(entry); err != nil {
				b.Fatalf("convert failed: %v", err)
			}
		}
	}
}
