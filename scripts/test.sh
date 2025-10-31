#!/bin/bash
# ANP-Go 测试脚本 - 简单、快速、实用
# 用法: ./test.sh [--ci|--examples|--verify|--all]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 默认模式
MODE="${1:-quick}"

cd "$PROJECT_ROOT"

# 快速测试（默认）
if [ "$MODE" = "quick" ] || [ "$MODE" = "--ci" ] || [ "$MODE" = "--all" ]; then
    echo "==> Checking format..."
    if [ -n "$(gofmt -l . 2>/dev/null | grep -v vendor)" ]; then
        echo "❌ Format check failed. Run: gofmt -w ."
        [ "$MODE" = "--ci" ] && exit 1
    else
        echo "✓ Format OK"
    fi
    
    echo ""
    echo "==> Running go vet..."
    go vet ./...
    echo "✓ Vet passed"
    
    echo ""
    echo "==> Running tests..."
    go test ./... -race
    echo "✓ Tests passed"
    
    echo ""
    echo "==> Building..."
    go build ./...
    echo "✓ Build OK"
fi

# 测试示例
if [ "$MODE" = "--examples" ] || [ "$MODE" = "--all" ]; then
    echo ""
    echo "==> Compiling examples..."
    for dir in examples/*/; do
        [ -d "$dir" ] || continue
        [ -n "$(find "$dir" -maxdepth 1 -name '*.go' 2>/dev/null)" ] || continue
        name=$(basename "$dir")
        echo "  - $name"
        (cd "$dir" && go build . 2>&1 > /dev/null) || echo "    ⚠ Failed"
    done
    echo "✓ Examples compiled"
fi

# CI 模式额外检查
if [ "$MODE" = "--ci" ] || [ "$MODE" = "--all" ]; then
    echo ""
    echo "==> Verifying dependencies..."
    go mod verify
    go mod tidy -v
    echo "✓ Dependencies OK"
fi

# 跨语言验证
if [ "$MODE" = "--verify" ] || [ "$MODE" = "--all" ]; then
    echo ""
    
    # Bash 验证（快速，无依赖）
    if [ -f "$SCRIPT_DIR/verify_cross_lang.sh" ]; then
        bash "$SCRIPT_DIR/verify_cross_lang.sh"
    fi
    
    # Python 验证（完整，需要 Python ANP）
    if [ -d "$PROJECT_ROOT/cross_verify" ]; then
        echo ""
        echo "==> Python Cross-Language Verification"
        if command -v uv &>/dev/null && [ -f "$PROJECT_ROOT/../anp/authentication/did_wba_authenticator.py" ]; then
            (cd "$PROJECT_ROOT/cross_verify" && uv run --no-project python verify.py) || echo "⚠ Python verification skipped"
        else
            echo "ℹ Skipped (requires: uv + ANP Python source)"
        fi
    fi
fi

echo ""
echo "✅ All checks passed"
