# ANP-Go 测试脚本

两个脚本，职责单一，简单高效。

## 快速开始

```bash
cd anp-go

# 快速测试（默认）- 格式、vet、test、build
./scripts/test.sh

# CI 模式 - 快速测试 + 依赖验证
./scripts/test.sh --ci

# 示例测试 - 编译所有示例
./scripts/test.sh --examples

# 跨语言验证 - Go/Python 一致性检查
./scripts/test.sh --verify

# 完整测试 - 以上所有
./scripts/test.sh --all
```

或直接运行跨语言验证：

```bash
# 独立运行跨语言验证
./scripts/verify_cross_lang.sh
```

## 模式说明

### 快速模式（默认）
最常用，本地开发时快速验证：
- ✓ 代码格式检查（gofmt）
- ✓ 静态分析（go vet）
- ✓ 单元测试（go test -race）
- ✓ 编译检查（go build）

**用途**：提交前检查
**耗时**：~30 秒

### CI 模式
用于持续集成，包含快速模式 + 依赖验证：
- ✓ 快速模式所有检查
- ✓ 依赖验证（go mod verify/tidy）
- ⚠ 格式检查失败时直接退出

**用途**：CI/CD 流水线
**耗时**：~30-45 秒

### 示例模式
编译所有示例程序，确保示例可用：
- ✓ 编译 examples/ 下所有 Go 程序

**用途**：发版前检查
**耗时**：~15 秒

### 跨语言验证模式
验证 Go 实现的数据结构正确性：
- ✓ DID 文档格式验证
- ✓ DID-WBA 认证头格式
- ✓ JSON 输出结构
- ✓ 随机性验证（nonce/timestamp）
- ✓ 多域名兼容性

**用途**：确保 Go 实现输出格式正确
**耗时**：~20-30 秒
**依赖**：仅需 Go，不依赖 Python ANP 模块

### 完整模式
运行所有测试，最全面的检查：
- ✓ 快速模式
- ✓ 示例模式
- ✓ 跨语言验证

**用途**：发版前最终检查
**耗时**：~60-90 秒

## CI/CD 集成

### GitHub Actions
```yaml
- name: Test
  run: cd anp-go && ./scripts/test.sh --ci

- name: Cross-language Verification
  run: cd anp-go && ./scripts/test.sh --verify
```

### GitLab CI
```yaml
test:
  script:
    - cd anp-go && ./scripts/test.sh --ci

verify:
  script:
    - cd anp-go && ./scripts/verify_cross_lang.sh
```

### 本地 Git Hooks
```bash
# .git/hooks/pre-commit
#!/bin/bash
cd anp-go && ./scripts/test.sh
```

## 常见问题

**Q: 格式检查失败怎么办？**
```bash
gofmt -w .
```

**Q: 某个示例编译失败？**  
示例模式会显示警告但不会失败，这是正常的（某些示例需要网络）。

**Q: 需要更详细的输出？**  
直接运行 go 命令：
```bash
go test -v ./...
go test -cover ./...
```

## 设计原则

- **KISS**：3 个核心组件，职责单一
- **Unix 哲学**：每个脚本做好一件事
  - `test.sh`: 代码质量检查
  - `verify_cross_lang.sh`: Go 数据结构验证（Bash）
  - `../cross_verify/`: Go/Python 跨语言验证（Python）
- **快速反馈**：默认模式 30 秒内完成
- **渐进式验证**：从简单到复杂，可选择验证深度

## 验证层次

### Level 1: 快速验证（test.sh 默认）
- Go 代码格式、静态分析、单元测试、编译
- 耗时: ~30秒
- 依赖: 仅 Go

### Level 2: 数据结构验证（verify_cross_lang.sh）
- Go 生成的 DID-WBA 格式验证
- 随机输入测试
- 耗时: ~30秒
- 依赖: 仅 Go + Bash

### Level 3: 跨语言验证（cross_verify/）
- Go vs Python 实现对比
- 完整的数据结构一致性检查
- 耗时: ~40秒
- 依赖: Go + Python ANP + uv

## 为什么不用 Makefile？

Bash 脚本更简单、更直接，不需要学习 Make 语法。对于测试这种简单任务，脚本足够了。

## 跨语言验证说明

`cross_verify/` 目录包含完整的 Go/Python 对比验证：
- 使用本地 ANP Python 源码
- 通过 uv 管理依赖
- 验证 5 个关键维度的一致性
- 详见: `../cross_verify/README.md`

## 贡献

保持脚本简单。如果需要添加功能，先问自己：
1. 是否真的需要？（YAGNI）
2. 能否简化为更简单的形式？（KISS）
3. 是否增加了不必要的复杂度？

简单永远胜过复杂。
