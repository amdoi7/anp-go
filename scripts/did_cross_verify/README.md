# DID-WBA 中间产物交叉验证

## 目标定义

验证 Go 和 Python 在 DID-WBA 认证生成过程中，**每个步骤**的中间产物都一致，快速定位差异。

## 认证流程与中间产物

```
Input (target URL, DID doc, private key)
    ↓
Step 1: 生成 nonce + timestamp
    → artifacts: nonce, timestamp, did
    ↓
Step 2: 构造签名 payload
    → artifacts: payload_json, payload_bytes
    ↓
Step 3: 计算签名
    → artifacts: signature_base64url
    ↓
Step 4: 组装认证头
    → artifacts: auth_header_string
    ↓
Output: Authorization Header
```

## 快速开始

```bash
# 1. 安装依赖
cd anp-go/scripts/did_cross_verify
pip install -r requirements.txt

# 2. 运行验证
python compare_artifacts.py

# 3. 查看报告
cat report.txt
```

## 中间产物定义

### 1. Step1: 参数生成
```json
{
  "did": "did:wba:example.com:agent",
  "nonce": "uuid-v4-string",
  "timestamp": "2025-10-30T12:00:00Z",
  "verification_method": "key-1",
  "service_domain": "example.com"
}
```

### 2. Step2: Payload 构造
```json
{
  "payload_struct": {
    "did": "...",
    "nonce": "...",
    "timestamp": "...",
    "verification_method": "..."
  },
  "payload_json": "{\"did\":..., \"nonce\":..., ...}",
  "payload_bytes_hex": "7b226469..."
}
```

### 3. Step3: 签名计算
```json
{
  "payload_hash_hex": "a1b2c3...",
  "signature_bytes_hex": "d4e5f6...",
  "signature_base64url": "RXLTzh_R49ZF..."
}
```

### 4. Step4: 认证头组装
```json
{
  "auth_header": "DIDWba did=\"...\", nonce=\"...\", ..."
}
```

## 使用方式

### 方式 1: 自动模式（推荐）
```bash
# 自动运行 Go 和 Python，对比中间产物
python compare_artifacts.py --auto
```

### 方式 2: 手动模式
```bash
# 1. 生成 Go 产物
cd ../../
go run scripts/did_cross_verify/go_generator.go

# 2. 生成 Python 产物
python scripts/did_cross_verify/py_generator.py

# 3. 对比
python scripts/did_cross_verify/compare_artifacts.py
```

### 方式 3: CI 集成
```yaml
- name: Cross-verify Artifacts
  run: |
    cd anp-go/scripts/did_cross_verify
    pip install -r requirements.txt
    python compare_artifacts.py --auto --ci
```

## 输出示例

```
============================================================
ANP DID-WBA Intermediate Artifacts Verification
============================================================

==> Step 1: Parameters Generation
✓ Go generated: artifacts/go_step1_params.json
✓ Python generated: artifacts/py_step1_params.json
✓ Fields matched: did, nonce, timestamp, verification_method
⚠ nonce differs (expected - each run generates unique value)
⚠ timestamp differs (expected - different generation time)
✓ did, verification_method identical

==> Step 2: Payload Construction
✓ Go generated: artifacts/go_step2_payload.json
✓ Python generated: artifacts/py_step2_payload.json
✓ payload_struct identical
✓ payload_json identical (after normalizing nonce/timestamp)
✓ payload_bytes_hex identical

==> Step 3: Signature Calculation
✓ Go generated: artifacts/go_step3_signature.json
✓ Python generated: artifacts/py_step3_signature.json
⚠ payload_hash differs (due to different nonce/timestamp)
⚠ signature differs (due to different payload)
✓ Signature lengths identical: 86 chars (base64url)
✓ Signature format valid: [A-Za-z0-9_-]+

==> Step 4: Auth Header Assembly
✓ Go generated: artifacts/go_step4_header.json
✓ Python generated: artifacts/py_step4_header.json
✓ Header format: DIDWba did="...", nonce="...", ...
✓ Field order identical
✓ Quotation marks consistent

============================================================
Summary
============================================================
✅ PASS: All structural checks passed
✅ PASS: Format consistency verified
✅ PASS: Algorithm compatibility confirmed

ℹ Note: Actual values differ due to random nonce/timestamp (expected)
ℹ To verify exact match, use fixed input mode:
  python compare_artifacts.py --fixed-input
```

## 高级功能

### 固定输入模式
使用预定义的 nonce 和 timestamp，验证完全一致：

```bash
python compare_artifacts.py --fixed-input \
  --nonce "fixed-nonce-12345" \
  --timestamp "2025-10-30T12:00:00Z"
```

### 差异报告
生成详细的差异报告：

```bash
python compare_artifacts.py --report-format html > diff_report.html
```

### 性能对比
测试两种实现的性能：

```bash
python compare_artifacts.py --benchmark
```

## CI/CD 集成

### GitHub Actions
```yaml
- name: Artifact Verification
  run: |
    cd anp-go/scripts/did_cross_verify
    pip install -r requirements.txt
    python compare_artifacts.py --auto --ci
```

### GitLab CI
```yaml
cross_verify_artifacts:
  script:
    - cd anp-go/scripts/did_cross_verify
    - pip install -r requirements.txt
    - python compare_artifacts.py --auto --ci
  artifacts:
    paths:
      - anp-go/scripts/did_cross_verify/artifacts/
      - anp-go/scripts/did_cross_verify/report.txt
```

## 故障排查

### 问题：签名总是不同
**原因**: nonce 和 timestamp 每次都随机生成  
**解决**: 使用 `--fixed-input` 模式

### 问题：payload 结构不同
**原因**: 字段顺序或格式差异  
**解决**: 检查 `artifacts/*/step2_payload.json` 的 `payload_json` 字段

### 问题：依赖安装失败
**解决**: 
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## 设计原则

1. **结构化对比**: 使用 `deepdiff` 而非文本 diff
2. **容错机制**: 允许随机值（nonce/timestamp）差异
3. **快速定位**: 精确到步骤级别的差异检测
4. **自动化**: 可集成 CI，一键执行
5. **可复现**: 支持固定输入模式

## 参考文档

- [DID-WBA 规范](../../docs/ap2/)
- [DeepDiff 文档](https://zepworks.com/deepdiff/)
- [测试最佳实践](../README.md)
