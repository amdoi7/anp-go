# ANP 跨语言验证

独立的验证项目，使用 PyPI 的 `agentnetworkprotocol` 包验证 Go 和 Python 实现的一致性。

## 快速开始

```bash
# 方式 1: 直接运行（推荐）
cd anp-go/cross_verify
uv run --no-project python verify.py

# 方式 2: 通过测试脚本
cd anp-go
./scripts/test.sh --verify

# 方式 3: 完整测试（包含跨语言验证）
./scripts/test.sh --all
```

## 验证内容

### 1. DID 文档加载
- ✓ Python 和 Go 都能正确加载同一个 DID 文档
- ✓ 提取的 DID ID 一致

### 2. 认证头格式
- ✓ 都使用 `DIDWba` 格式
- ✓ 包含必需字段：`did`, `nonce`, `timestamp`, `signature`
- ✓ 字段顺序和分隔符一致

### 3. JSON 结构
- ✓ 字段名称一致
- ✓ 数据类型一致
- ✓ 必需字段都存在

### 4. 签名格式
- ✓ 使用 base64url 编码（无 padding）
- ✓ 签名长度合理
- ✓ 字符集正确

### 5. 多次生成
- ✓ 每次生成的 nonce 不同（随机性）
- ✓ 每次生成的 timestamp 不同
- ✓ DID 保持一致
- ✓ 签名不同（因为 nonce/timestamp 不同）

## 输出示例

```
============================================================
ANP Cross-Language Verification (Go vs Python)
============================================================
Using agentnetworkprotocol package from PyPI
✓ ANP-Go root: /path/to/anp-go

==> Verifying DID Document
✓ Python loaded DID: did:wba:didhost.cc:public
✓ Go loaded DID successfully

==> Verifying Auth Header Format
✓ Python generated: DIDWba did="did:wba:didhost.cc:public"...
✓ Go generated: DIDWba did="did:wba:didhost.cc:public"...
✓ Both use DIDWba format
✓ Both contain required fields: did, nonce, timestamp, signature

==> Verifying JSON Structure
✓ Python JSON fields: ['did', 'nonce', 'timestamp', 'verification_method', 'signature']
✓ Go JSON fields: ['did', 'nonce', 'timestamp', 'verification_method', 'signature']
✓ Common fields: ['did', 'nonce', 'signature', 'timestamp', 'verification_method']
✓ All required fields present in both

==> Verifying Signature Format
✓ Python signature: RXLTzh_R49ZFOJRl0CDx6EEvKRUS... (len=86)
✓ Go signature: xz64Pu1E1WQtvda6uWrK2Ndxxz-... (len=86)
✓ Both use valid base64url encoding

==> Verifying Multiple Generations
✓ Python: Each generation has unique nonce
✓ Go: Each generation has unique nonce
✓ DIDs remain consistent across generations

============================================================
Summary
============================================================
✅ PASS: DID Document
✅ PASS: Auth Header Format
✅ PASS: JSON Structure
✅ PASS: Signature Format
✅ PASS: Multiple Generations

Total: 5/5 passed

🎉 All cross-language verifications passed!
```

## CI/CD 集成

### GitHub Actions
```yaml
- name: Cross-language Verification
  run: |
    cd anp-go/cross_verify
    uv sync
    uv run python verify.py
```

### GitLab CI
```yaml
cross_verify:
  script:
    - cd anp-go/cross_verify
    - uv sync
    - uv run python verify.py
```

## 依赖

- **Python**: >= 3.10
- **uv**: Python 包管理器
- **Go**: >= 1.20
- **agentnetworkprotocol**: 从 PyPI 安装

## 设计原则

- **独立性**: 不依赖本地 ANP 源码，只使用 PyPI 包
- **真实性**: 使用真实的 PyPI 发布版本
- **全面性**: 验证格式、结构、随机性等多个维度
- **自动化**: 可集成到 CI/CD 流程

## 故障排查

### ANP 包未安装
```bash
❌ ANP package not installed. Run: uv sync
```
**解决**: `cd cross_verify && uv sync`

### Go 工具链问题
```bash
❌ Go generation failed
```
**解决**: 确保 Go 已安装且在 PATH 中

### 测试凭证缺失
```bash
❌ Test credentials not found
```
**解决**: 确保在 `examples/did_public/` 下有测试 DID 文档和私钥
