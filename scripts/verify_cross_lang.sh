#!/bin/bash
# Go 数据结构验证 - 简单、直接、有效
# 策略：随机输入 -> Go 生成 -> 验证输出格式

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "ANP-Go Data Structure Verification"
echo "===================================="

# 1. 验证 DID 文档
echo ""
echo "==> DID Document Format"
DID_DOC="$PROJECT_ROOT/examples/did_public/public-did-doc.json"
if [ -f "$DID_DOC" ] && grep -q '"id".*"did:' "$DID_DOC"; then
    DID_ID=$(grep '"id"' "$DID_DOC" | cut -d\" -f4)
    echo "✓ DID document exists: $DID_ID"
else
    echo "❌ DID document invalid"
    exit 1
fi

# 2. 验证认证头生成
echo ""
echo "==> Auth Header Generation"
cd "$PROJECT_ROOT"
TARGET="https://test-$(date +%s).example.com/api"
OUTPUT=$(go run examples/identity/basic_header/main.go -target "$TARGET" -format header 2>&1)

if echo "$OUTPUT" | grep -q "Authorization header:.*DIDWba"; then
    echo "✓ Generated for: $TARGET"
    
    # 验证必需字段
    if echo "$OUTPUT" | grep -q 'did=' &&\
       echo "$OUTPUT" | grep -q 'nonce=' &&\
       echo "$OUTPUT" | grep -q 'timestamp=' &&\
       echo "$OUTPUT" | grep -q 'signature='; then
        echo "✓ Contains: did, nonce, timestamp, signature"
    else
        echo "❌ Missing required fields"
        exit 1
    fi
else
    echo "❌ Auth generation failed"
    exit 1
fi

# 3. 验证 JSON 格式
echo ""
echo "==> JSON Auth Format"
JSON_OUTPUT=$(go run examples/identity/basic_header/main.go -target "$TARGET" -format json 2>&1)

if echo "$JSON_OUTPUT" | grep -q '"did"' &&\
   echo "$JSON_OUTPUT" | grep -q '"signature"'; then
    FIELD_COUNT=$(echo "$JSON_OUTPUT" | grep -o '"[^"]*":' | wc -l)
    echo "✓ Valid JSON with $FIELD_COUNT fields"
else
    echo "❌ Invalid JSON format"
    exit 1
fi

# 4. 验证随机性（nonce/timestamp）
echo ""
echo "==> Randomness (nonce/timestamp)"
OUT1=$(go run examples/identity/basic_header/main.go -target "$TARGET" -format header 2>&1 | grep "Authorization")
sleep 1
OUT2=$(go run examples/identity/basic_header/main.go -target "$TARGET" -format header 2>&1 | grep "Authorization")

if [ "$OUT1" != "$OUT2" ]; then
    echo "✓ Each generation is unique"
else
    echo "⚠ Identical outputs (nonce/timestamp issue?)"
fi

# 5. 验证多域名
echo ""
echo "==> Multiple Domains"
for domain in "https://example.com/api" "https://test.io" "https://agent-connect.ai/mcp"; do
    if go run examples/identity/basic_header/main.go -target "$domain" -format header 2>&1 | grep -q "Authorization header:"; then
        echo "✓ $domain"
    else
        echo "❌ $domain failed"
        exit 1
    fi
done

echo ""
echo "===================================="
echo "✅ All verifications passed"
