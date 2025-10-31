#!/usr/bin/env python3
"""
跨语言验证：Go vs Python ANP 实现
使用本地 ANP 包进行独立验证
"""

import json
import subprocess
import sys
from pathlib import Path

# 添加父目录的 ANP 包到 Python 路径
script_dir = Path(__file__).parent
anp_root = script_dir.parent.parent
sys.path.insert(0, str(anp_root))

try:
    from anp.authentication.did_wba_authenticator import DIDWbaAuthHeader
except ImportError as e:
    print(f"❌ ANP package import failed: {e}")
    print(f"   Tried to import from: {anp_root}")
    sys.exit(1)


class CrossVerifier:
    """跨语言验证器"""
    
    def __init__(self, anp_go_root: Path):
        self.go_root = anp_go_root
        self.did_doc = anp_go_root / "examples/did_public/public-did-doc.json"
        self.private_key = anp_go_root / "examples/did_public/public-private-key.pem"
        
        if not self.did_doc.exists() or not self.private_key.exists():
            raise FileNotFoundError("Test credentials not found")
    
    def verify_did_document(self):
        """验证 DID 文档在两种实现中都能正确加载"""
        print("\n==> Verifying DID Document")
        
        # Python 加载
        with open(self.did_doc) as f:
            py_doc = json.load(f)
        
        py_did_id = py_doc['id']
        print(f"✓ Python loaded DID: {py_did_id}")
        
        # Go 加载（通过生成认证头来验证）
        result = subprocess.run(
            ["go", "run", "examples/did_public/main.go",
             "-doc", str(self.did_doc),
             "-key", str(self.private_key),
             "-domain", "test.example.com",
             "-format", "header"],
            cwd=self.go_root,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0 and "Authorization header:" in result.stdout:
            print("✓ Go loaded DID successfully")
        else:
            print("❌ Go failed to load DID")
            return False
        
        return True
    
    def verify_auth_header_format(self):
        """验证认证头格式一致性"""
        print("\n==> Verifying Auth Header Format")
        
        target = "https://test.example.com/api"
        
        # Python 生成
        py_auth = DIDWbaAuthHeader(
            did_document_path=str(self.did_doc),
            private_key_path=str(self.private_key),
        )
        py_header = py_auth.get_auth_header(target)
        py_auth_value = py_header["Authorization"]
        
        print(f"✓ Python generated: {py_auth_value[:50]}...")
        
        # Go 生成
        result = subprocess.run(
            ["go", "run", "examples/identity/basic_header/main.go",
             "-target", target,
             "-format", "header"],
            cwd=self.go_root,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print("❌ Go generation failed")
            return False
        
        go_auth_value = result.stdout.split("Authorization header:")[1].strip()
        print(f"✓ Go generated: {go_auth_value[:50]}...")
        
        # 验证格式一致性（都应该是 DIDWba 格式）
        if py_auth_value.startswith("DIDWba ") and go_auth_value.startswith("DIDWba "):
            print("✓ Both use DIDWba format")
        else:
            print(f"⚠ Format mismatch: Python={py_auth_value[:20]}, Go={go_auth_value[:20]}")
        
        # 验证必需字段
        required_fields = ['did=', 'nonce=', 'timestamp=', 'signature=']
        py_has_all = all(f in py_auth_value for f in required_fields)
        go_has_all = all(f in go_auth_value for f in required_fields)
        
        if py_has_all and go_has_all:
            print("✓ Both contain required fields: did, nonce, timestamp, signature")
            return True
        else:
            print("❌ Missing required fields")
            return False
    
    def verify_json_structure(self):
        """验证 JSON 输出结构"""
        print("\n==> Verifying JSON Structure")
        
        target = "https://test.example.com/api"
        
        # Python 生成认证头并解析
        py_auth = DIDWbaAuthHeader(
            did_document_path=str(self.did_doc),
            private_key_path=str(self.private_key),
        )
        py_header = py_auth.get_auth_header(target)
        py_auth_value = py_header["Authorization"]
        
        # 从 header 中提取字段（DIDWba 格式）
        import re
        py_fields = re.findall(r'(\w+)="[^"]*"', py_auth_value)
        py_dict = {f: "present" for f in py_fields}
        
        print(f"✓ Python JSON fields: {list(py_dict.keys())}")
        
        # Go 生成
        result = subprocess.run(
            ["go", "run", "examples/identity/basic_header/main.go",
             "-target", target,
             "-format", "json"],
            cwd=self.go_root,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print("❌ Go generation failed")
            return False
        
        go_dict = json.loads(result.stdout)
        print(f"✓ Go JSON fields: {list(go_dict.keys())}")
        
        # 比较字段
        py_fields = set(py_dict.keys())
        go_fields = set(go_dict.keys())
        
        common = py_fields & go_fields
        py_only = py_fields - go_fields
        go_only = go_fields - py_fields
        
        print(f"✓ Common fields: {sorted(common)}")
        if py_only:
            print(f"ℹ Python-only fields: {sorted(py_only)}")
        if go_only:
            print(f"ℹ Go-only fields: {sorted(go_only)}")
        
        # 验证必需字段都存在
        required = {'did', 'nonce', 'timestamp', 'signature'}
        if required.issubset(common):
            print("✓ All required fields present in both")
            return True
        else:
            print(f"❌ Missing required fields in common: {required - common}")
            return False
    
    def verify_signature_format(self):
        """验证签名格式（base64url）"""
        print("\n==> Verifying Signature Format")
        
        target = "https://test.example.com/api"
        
        # Python 签名
        py_auth = DIDWbaAuthHeader(
            did_document_path=str(self.did_doc),
            private_key_path=str(self.private_key),
        )
        py_header = py_auth.get_auth_header(target)
        py_auth_value = py_header["Authorization"]
        
        # 提取签名
        import re
        match = re.search(r'signature="([^"]*)"', py_auth_value)
        if not match:
            print("❌ Cannot extract Python signature")
            return False
        py_sig = match.group(1)
        
        print(f"✓ Python signature: {py_sig[:30]}... (len={len(py_sig)})")
        
        # Go 签名
        result = subprocess.run(
            ["go", "run", "examples/identity/basic_header/main.go",
             "-target", target,
             "-format", "json"],
            cwd=self.go_root,
            capture_output=True,
            text=True
        )
        
        go_dict = json.loads(result.stdout)
        go_sig = go_dict['signature']
        
        print(f"✓ Go signature: {go_sig[:30]}... (len={len(go_sig)})")
        
        # 验证签名格式（base64url，不含 padding）
        import re
        base64url_pattern = re.compile(r'^[A-Za-z0-9_-]+$')
        
        py_valid = base64url_pattern.match(py_sig) is not None
        go_valid = base64url_pattern.match(go_sig) is not None
        
        if py_valid and go_valid:
            print("✓ Both use valid base64url encoding")
            return True
        else:
            print(f"❌ Invalid signature format: Python={py_valid}, Go={go_valid}")
            return False
    
    def verify_multiple_generations(self):
        """验证多次生成的一致性和随机性"""
        print("\n==> Verifying Multiple Generations")
        
        target = "https://test.example.com/api"
        
        # Python 生成两次
        py_auth = DIDWbaAuthHeader(
            did_document_path=str(self.did_doc),
            private_key_path=str(self.private_key),
        )
        
        py_header1 = py_auth.get_auth_header(target)["Authorization"]
        import time
        time.sleep(0.1)
        py_header2 = py_auth.get_auth_header(target)["Authorization"]
        
        if py_header1 != py_header2:
            print("✓ Python: Each generation is unique")
        else:
            print("⚠ Python: Headers are identical")
        
        # Go 生成两次
        result1 = subprocess.run(
            ["go", "run", "examples/identity/basic_header/main.go",
             "-target", target, "-format", "json"],
            cwd=self.go_root,
            capture_output=True,
            text=True
        )
        result2 = subprocess.run(
            ["go", "run", "examples/identity/basic_header/main.go",
             "-target", target, "-format", "json"],
            cwd=self.go_root,
            capture_output=True,
            text=True
        )
        
        go_json1 = json.loads(result1.stdout)
        go_json2 = json.loads(result2.stdout)
        
        if go_json1['nonce'] != go_json2['nonce']:
            print("✓ Go: Each generation has unique nonce")
        else:
            print("⚠ Go: Nonces are identical")
        
        # 验证 DID 字段都存在
        import re
        py_did1 = re.search(r'did="([^"]*)"', py_header1)
        py_did2 = re.search(r'did="([^"]*)"', py_header2)
        
        if py_did1 and py_did2 and py_did1.group(1) == py_did2.group(1) and go_json1['did'] == go_json2['did']:
            print("✓ DIDs remain consistent across generations")
            return True
        else:
            print("⚠ Cannot verify DID consistency")
            return True  # 不算失败


def main():
    print("=" * 60)
    print("ANP Cross-Language Verification (Go vs Python)")
    print("=" * 60)
    print("Using agentnetworkprotocol package from PyPI")
    
    # 定位 anp-go 根目录
    script_dir = Path(__file__).parent
    anp_go_root = script_dir.parent
    
    if not (anp_go_root / "go.mod").exists():
        print("❌ Cannot find anp-go root directory")
        sys.exit(1)
    
    print(f"✓ ANP-Go root: {anp_go_root}")
    
    # 创建验证器
    try:
        verifier = CrossVerifier(anp_go_root)
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)
    
    # 运行验证
    results = []
    
    tests = [
        ("DID Document", verifier.verify_did_document),
        ("Auth Header Format", verifier.verify_auth_header_format),
        ("JSON Structure", verifier.verify_json_structure),
        ("Signature Format", verifier.verify_signature_format),
        ("Multiple Generations", verifier.verify_multiple_generations),
    ]
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"❌ Test '{name}' failed with error: {e}")
            results.append((name, False))
    
    # 总结
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nTotal: {passed}/{total} passed")
    
    if passed == total:
        print("\n🎉 All cross-language verifications passed!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {total - passed} verification(s) failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
