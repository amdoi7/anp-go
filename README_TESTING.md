# ANP-Go 测试指南

本文档说明如何使用 anp-go 的测试工具。

## 目录结构

```
anp-go/
├── scripts/               # 测试脚本
│   ├── test.sh           # 主测试脚本
│   ├── verify_cross_lang.sh  # Bash 数据验证
│   └── README.md         # 详细文档
└── cross_verify/         # Python 跨语言验证
    ├── verify.py         # 验证脚本
    ├── pyproject.toml    # 依赖配置
    └── README.md         # 使用说明
```

## 快速开始

```bash
# 1. 日常开发 - 快速测试
./scripts/test.sh

# 2. PR 前检查 - CI 模式
./scripts/test.sh --ci

# 3. 发版前 - 完整验证
./scripts/test.sh --all
```

## 测试层次

### 🚀 Level 1: 快速测试（默认）
```bash
./scripts/test.sh
```

**包含:**
- ✓ 代码格式检查 (gofmt)
- ✓ 静态分析 (go vet)
- ✓ 单元测试 (go test -race)
- ✓ 编译检查 (go build)

**耗时:** ~30秒  
**依赖:** 仅 Go  
**用途:** 本地开发时频繁运行

### 🔍 Level 2: 数据结构验证
```bash
./scripts/test.sh --verify
# 或
./scripts/verify_cross_lang.sh
```

**包含:**
- ✓ DID 文档格式
- ✓ DID-WBA 认证头格式
- ✓ JSON 输出结构
- ✓ 随机性验证（nonce/timestamp）
- ✓ 多域名兼容性

**耗时:** ~30秒  
**依赖:** Go + Bash  
**用途:** 验证输出格式正确性

### 🎯 Level 3: 跨语言验证
```bash
cd cross_verify
uv run --no-project python verify.py
# 或通过主脚本
cd ..
./scripts/test.sh --all
```

**包含:**
- ✓ Go vs Python 实现对比
- ✓ DID 文档加载一致性
- ✓ 认证头格式一致性
- ✓ JSON 结构一致性
- ✓ 签名格式一致性
- ✓ 多次生成一致性

**耗时:** ~40秒  
**依赖:** Go + Python ANP + uv  
**用途:** 确保两种语言实现兼容

## 所有选项

```bash
./scripts/test.sh           # 快速测试（默认）
./scripts/test.sh --ci      # CI 模式（+ 依赖验证）
./scripts/test.sh --examples  # 编译所有示例
./scripts/test.sh --verify  # 数据结构 + 跨语言验证
./scripts/test.sh --all     # 完整测试（全部）
```

## CI/CD 集成

### GitHub Actions
```yaml
name: ANP-Go Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Quick Tests
        run: cd anp-go && ./scripts/test.sh --ci
      
      - name: Data Structure Verification
        run: cd anp-go && ./scripts/verify_cross_lang.sh
      
      - name: Cross-language Verification
        run: |
          cd anp-go/cross_verify
          pip install uv
          uv run --no-project python verify.py
```

### GitLab CI
```yaml
test_quick:
  script:
    - cd anp-go && ./scripts/test.sh --ci

test_verify:
  script:
    - cd anp-go && ./scripts/verify_cross_lang.sh

test_cross_lang:
  script:
    - cd anp-go/cross_verify
    - pip install uv
    - uv run --no-project python verify.py
```

## 常见问题

### Q: 格式检查失败？
```bash
# 自动修复
gofmt -w .
```

### Q: 跨语言验证跳过？
需要确保:
1. 安装了 uv: `pip install uv` 或 `brew install uv`
2. ANP Python 源码在父目录: `../anp/`

### Q: 如何只运行特定测试？
```bash
# 只运行单元测试
go test ./...

# 只测试某个包
go test ./anp_auth/...

# 详细输出
go test -v ./...
```

## 最佳实践

### 开发工作流
```bash
# 1. 修改代码
vim anp_auth/authenticator.go

# 2. 快速检查
./scripts/test.sh

# 3. 提交前
./scripts/test.sh --ci
```

### PR 检查清单
- [ ] `./scripts/test.sh --ci` 通过
- [ ] `./scripts/verify_cross_lang.sh` 通过
- [ ] 代码已格式化 (`gofmt -w .`)
- [ ] 所有新功能有测试

### 发版前检查
```bash
# 完整测试
./scripts/test.sh --all

# 确认所有测试通过
echo $?  # 应该输出 0
```

## 性能基准

在 MacBook Pro (M1) 上的测试时间:

| 测试模式 | 耗时 | 适用场景 |
|---------|------|---------|
| 快速测试 | 30s | 开发时频繁运行 |
| CI 模式 | 45s | PR 检查 |
| 数据验证 | 30s | 格式验证 |
| 跨语言验证 | 40s | 发版前 |
| 完整测试 | 90s | 发版前最终检查 |

## 参考文档

- [scripts/README.md](scripts/README.md) - 测试脚本详细说明
- [cross_verify/README.md](cross_verify/README.md) - 跨语言验证说明
- [../CLAUDE.md](../CLAUDE.md) - 项目开发指南
