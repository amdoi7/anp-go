# ANP Go SDK

该目录包含 ANP 在 Go 语言下的核心实现。为了兼顾性能与易用性，代码被拆分为三个互补模块：

- `anp/session`：高层会话封装，组合认证、HTTP 传输与文档解析，提供最少心智的调用接口。
- `anp/anp_auth`：身份模块，暴露 DID-WBA 认证与校验的底层原语，可独立复用。
- `anp/anp_crawler`：底层抓取/解析构件，被 `session` 复用，也支持高级用户直接调用。

## 模块简介

### `anp/session`
- `session.Config`：配置 DID 文档、私钥、本地认证器、自定义 HTTP 客户端/解析器等。
- `session.New`：返回 `*Session`，默认最多并发 5 个请求，可通过 `MaxConcurrent` 调整。
- 核心方法：
  - `Fetch(ctx, url)`：抓取并解析单个文档。
  - `FetchBatch(ctx, urls)`：并发抓取，尊重并发上限。
  - `Invoke(ctx, method, target, headers, body)`：发送泛型 HTTP 请求（例如 JSON-RPC）。
  - `ExecuteTool(ctx, doc, method, params)`：遍历文档中解析出的接口并执行指定方法。

### `anp/anp_auth`
- `Authenticator`：`NewAuthenticator(Config)` 后可调用 `GenerateHeader`、`GenerateJSON`、`UpdateFromResponse`、`ClearToken` 等方法。
- 底层纯函数：`GenerateAuthHeader`、`GenerateAuthJSON`、`VerifyAuthJSONBytes`、`DidWbaVerifier`、`LoadJWT*FromPEM`，方便自定义系统集成。
- 不依赖 HTTP，调用者控制传输逻辑。

### `anp/anp_crawler`
- `Client`、`Parser`、`InterfaceEntry`、`ANPInterface` 等基础构件，`session` 默认实现基于它们。
- 使用者可替换默认 Parser/Converter，或直接复用 `Client.Fetch` 实现细粒度控制。

## 快速开始

### 高层会话
```go
sess, err := session.New(session.Config{
    DIDDocumentPath: "examples/did_public/public-did-doc.json",
    PrivateKeyPath:  "examples/did_public/public-private-key.pem",
    HTTP:            session.HTTPConfig{Timeout: 20 * time.Second},
})
if err != nil {
    panic(err)
}

doc, err := sess.Fetch(context.Background(), "https://agent-connect.ai/mcp/agents/amap/ad.json")
if err != nil {
    panic(err)
}
fmt.Println(doc.ContentString())
```

### 底层身份工具
```go
auth, err := anp_auth.NewAuthenticator(anp_auth.Config{
    DIDDocumentPath: "examples/did_public/public-did-doc.json",
    PrivateKeyPath:  "examples/did_public/public-private-key.pem",
})
if err != nil {
    panic(err)
}

header, _ := auth.GenerateHeader("https://agent-connect.ai/api")
payload, _ := auth.GenerateJSON("https://agent-connect.ai/api")
bytes, _ := payload.Marshal()
ok, msg, _ := anp_auth.VerifyAuthJSONBytes(bytes, payload.Document, "agent-connect.ai")
fmt.Println(header["Authorization"], ok, msg)
```

## 示例
- `examples/fetch_amap`、`examples/hotel_booking`：使用 `session` 的端到端示例。
- `examples/identity/basic_header`、`examples/identity/verifier`：演示 `anp_auth` 的独立用法。

运行示例前请确保在仓库根目录执行 `uv sync` 或配置好 Go 环境，随后在 `anp-go` 目录下：
```bash
go run examples/fetch_amap/main.go
go run examples/identity/basic_header/main.go
```

## 测试
```bash
go test ./...
```

## 贡献
欢迎提交 Issue 或 PR，一起完善 ANP Go SDK。
