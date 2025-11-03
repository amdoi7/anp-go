# ANP Go SDK

该目录包含 ANP 在 Go 语言下的核心实现。为了兼顾性能与易用性，代码被拆分为三个互补模块：

- `anp/session`：高层会话封装，组合认证、HTTP 传输与文档解析，提供最少心智的调用接口。
- `anp/anp_auth`：身份模块，提供 DID-WBA 认证与校验，包括服务端中间件和客户端 Transport。
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
- **DID-WBA 认证**: 实现去中心化身份认证和验证
- **服务端**: `Middleware(verifier)` 提供标准 HTTP 中间件，自动验证请求
- **客户端**: `NewClient(authenticator)` 提供自动添加认证头的 HTTP 客户端
- **底层 API**: `Authenticator`、`DidWbaVerifier`、JWT 加载等，支持高级自定义集成
- **安全特性**: 强制外部 `NonceValidator` 防止重放攻击，支持分布式部署
- 详见 [anp_auth/README.md](./anp_auth/README.md) 获取完整文档

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

### 服务端中间件
```go
import "github.com/openanp/anp-go/anp_auth"

// 创建 nonce 验证器
nonceValidator := anp_auth.NewMemoryNonceValidator(6 * time.Minute)

// 创建验证器
verifier, err := anp_auth.NewDidWbaVerifier(anp_auth.DidWbaVerifierConfig{
    JWTPublicKeyPEM:       []byte(publicKey),
    JWTPrivateKeyPEM:      []byte(privateKey),
    NonceValidator:        nonceValidator,
    AccessTokenExpiration: 60 * time.Minute,
})

// 应用中间件
http.Handle("/api/", anp_auth.Middleware(verifier)(protectedHandler))
```

### 客户端自动认证
```go
auth, err := anp_auth.NewAuthenticator(anp_auth.Config{
    DIDDocumentPath: "did-doc.json",
    PrivateKeyPath:  "private-key.pem",
})

// 创建自动认证的客户端
client := anp_auth.NewClient(auth)

// 发起请求 - 自动添加认证头！
resp, err := client.Get("https://api.example.com/profile")
```

## 示例
- `examples/fetch_amap`、`examples/hotel_booking`：使用 `session` 的端到端示例
- `examples/middleware_server`：展示服务端 DID-WBA 中间件使用
- `examples/transport_client`：展示客户端自动认证 Transport
- `examples/identity/basic_header`、`examples/identity/verifier`：底层 API 示例

运行示例：
```bash
# 高层会话
go run examples/fetch_amap/main.go

# 服务端中间件
go run examples/middleware_server/main.go

# 客户端 Transport
go run examples/transport_client/main.go -url https://api.example.com/endpoint

# 底层认证
go run examples/identity/basic_header/main.go
```

## 测试
```bash
# 运行所有测试
go test ./...

# 带竞态检测
go test -race ./...

# 详细输出
go test -v ./anp_auth/...
```

## 架构特性

### 模块化设计
- **session**: 高层 API，最少心智负担
- **anp_auth**: 可独立使用的认证模块
- **anp_crawler**: 底层抓取/解析构件

### 生产环境就绪
- **强制安全**: NonceValidator 必须提供，防止重放攻击
- **分布式友好**: 支持 Redis/数据库等外部 nonce 存储
- **标准兼容**: 使用标准 SHA-256 哈希，符合工业最佳实践
- **并发安全**: 通过竞态检测测试

### Go 哲学
- **接口优先**: 小而精的接口，易于扩展
- **组合优于继承**: 使用标准 `http.Handler` 和 `http.RoundTripper`
- **显式优于隐式**: 所有配置项明确声明
- **错误即值**: 使用 Go 标准错误处理

## 文档

- [anp_auth 完整文档](./anp_auth/README.md) - DID-WBA 认证详细指南
- [session 文档](./session/README.md) - 高层会话 API
- [开发计划](./.prd/DEVELOPMENT_PLAN.md) - 架构决策和路线图

## 贡献
欢迎提交 Issue 或 PR，一起完善 ANP Go SDK。请参考 [CODE_REVIEW.md](../CODE_REVIEW.md) 了解编码规范。
