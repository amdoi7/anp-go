# session

`session` 包提供 Go 语言下的高层 ANP 会话封装，用于快速组合认证、HTTP 抓取与文档解析。

## 核心类型

### `Config`
- `DIDDocumentPath` / `PrivateKeyPath`：默认从文件加载 DID 与私钥。
- `Authenticator`：可直接传入自定义 `*anp_auth.Authenticator`。
- `HTTP`：自定义 `*http.Client` 或超时配置。
- `Parser`：注入自定义解析器/转换器。
- `MaxConcurrent`：并发抓取上限（默认 5）。
- `Logger`：可选 `*slog.Logger`。

### `Session`
- `Fetch(ctx, url)`：抓取并解析单个文档。
- `FetchBatch(ctx, urls)`：并发请求，尊重并发上限。
- `Invoke(ctx, method, target, headers, body)`：发送通用 HTTP 请求。
- `ExecuteTool(ctx, doc, method, params)`：执行 JSON-RPC 工具方法（文档中首个匹配的接口）。
- `ListInterfaces(doc)` / `ListAgents(doc)`：访问解析出的接口与代理。
- `Document.ContentString()`：返回文档原始文本。

## 快速示例
```go
sess, err := session.New(session.Config{
    DIDDocumentPath: "examples/did_public/public-did-doc.json",
    PrivateKeyPath:  "examples/did_public/public-private-key.pem",
})
if err != nil {
    panic(err)
}

doc, err := sess.Fetch(context.Background(), "https://agent-connect.ai/mcp/agents/amap/ad.json")
if err != nil {
    panic(err)
}
fmt.Println(session.ListInterfaces(doc))
```

## 扩展用法
- 自定义认证器或 HTTP 客户端：`Config.Authenticator`、`Config.HTTP.Client`
- 自定义解析器：实现 `anp_crawler.Parser`
- 并发控制：通过 `Config.MaxConcurrent` 调整；如需更复杂调度，可自建 goroutine + `session.Fetch`

## 运行示例
```bash
go run examples/fetch_amap/main.go
```

## 测试
```bash
go test ./...
```

## 并行抓取建议

`Session` 本身提供同步方法。若需要在调用侧并发抓取多个 URL，建议使用 `context` + `errgroup` + `semaphore`：

```go
import (
    "context"
    "fmt"
    "golang.org/x/sync/errgroup"
    "golang.org/x/sync/semaphore"
    "anp/session"
)

func fetchMany(ctx context.Context, sess *session.Session, urls []string, limit int64) ([]*session.Document, error) {
    if len(urls) == 0 {
        return nil, nil
    }

    if limit <= 0 {
        limit = 5
    }

    sem := semaphore.NewWeighted(limit)
    g, ctx := errgroup.WithContext(ctx)
    docs := make([]*session.Document, len(urls))

    for i, url := range urls {
        i, url := i, url
        if err := sem.Acquire(ctx, 1); err != nil {
            return nil, err
        }
        g.Go(func() error {
            defer sem.Release(1)
            doc, err := sess.Fetch(ctx, url)
            if err != nil {
                return fmt.Errorf("fetch %s: %w", url, err)
            }
            docs[i] = doc
            return nil
        })
    }

    if err := g.Wait(); err != nil {
        return nil, err
    }
    return docs, nil
}
```

- 使用 `context` 控制超时/取消，任何一个请求失败都会取消剩余任务。
- `semaphore` 控制最大并发数（默认 5）；也可换成 channel 或自定义池。
- 保持库层同步接口，调用方可灵活组合，符合 KISS & YAGNI 思想。

