import urllib.parse
import os


def banner():
    print("=" * 60)
    print("        🚀 专属 Clash Meta 配置文件生成器 v3.1")
    print("=" * 60)
    print("   功能说明：")
    print("   1. 自动识别 VLESS (Reality / WS+TLS)")
    print("   2. 支持选择 [GitHub 自动更新规则] 或 [本地简易规则]")
    print("=" * 60)


def parse_vless(url):
    try:
        if not url.startswith("vless://"):
            return None, "错误：必须以 vless:// 开头"

        parsed = urllib.parse.urlparse(url.strip())
        params = urllib.parse.parse_qs(parsed.query)

        uuid = parsed.username
        server = parsed.hostname
        port = parsed.port
        name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "我的节点"

        security = params.get("security", [""])[0]
        net_type = params.get("type", ["tcp"])[0]

        node = {
            "name": name,
            "server": server,
            "port": port,
            "uuid": uuid,
            "type": "unknown"
        }

        if security == "reality":
            node["type"] = "reality"
            node["flow"] = params.get("flow", ["xtls-rprx-vision"])[0]
            node["sni"] = params.get("sni", [""])[0]
            node["fp"] = params.get("fp", ["chrome"])[0]
            node["pbk"] = params.get("pbk", [""])[0]
            node["sid"] = params.get("sid", [""])[0]
            if not node["pbk"]:
                return None, "Reality 节点缺少 pbk 参数"

        elif net_type == "ws":
            node["type"] = "ws"
            host = params.get("host", [""])[0]
            if not host:
                host = params.get("sni", [""])[0]
            if not host:
                host = server
            node["host"] = host
            node["path"] = params.get("path", ["/"])[0]
            node["sni"] = params.get("sni", [host])[0]
            # 检查是否有TLS
            node["tls"] = security in ["tls", ""]
            # 获取端口判断是否TLS
            if port == 443:
                node["tls"] = True

        else:
            node["type"] = "tls"
            node["sni"] = params.get("sni", [server])[0]

        return node, None
    except Exception as e:
        return None, f"解析异常: {str(e)}"


def build_proxy_block(node):
    """单独构建 proxy 块，确保缩进干净"""
    lines = []
    lines.append(f'  - name: "{node["name"]}"')
    lines.append('    type: vless')
    lines.append(f'    server: {node["server"]}')
    lines.append(f'    port: {node["port"]}')
    lines.append(f'    uuid: {node["uuid"]}')
    lines.append('    udp: true')

    if node["type"] == "reality":
        lines.append('    network: tcp')
        lines.append('    tls: true')
        lines.append(f'    flow: {node["flow"]}')
        lines.append(f'    servername: {node["sni"]}')
        lines.append(f'    client-fingerprint: {node["fp"]}')
        lines.append('    reality-opts:')
        lines.append(f'      public-key: {node["pbk"]}')
        lines.append(f'      short-id: {node["sid"]}')

    elif node["type"] == "ws":
        lines.append('    network: ws')
        use_tls = node.get("tls", True)
        if use_tls:
            lines.append('    tls: true')
            lines.append('    skip-cert-verify: true')
            lines.append(f'    servername: {node["sni"]}')
            lines.append('    client-fingerprint: chrome')
        else:
            lines.append('    tls: false')
        lines.append('    ws-opts:')
        lines.append(f'      path: "{node["path"]}"')
        lines.append('      headers:')
        lines.append(f'        Host: {node["host"]}')

    else:  # 普通 tls
        lines.append('    network: tcp')
        lines.append('    tls: true')
        lines.append(f'    servername: {node["sni"]}')
        lines.append('    client-fingerprint: chrome')

    return '\n'.join(lines)


def generate_content(node, rule_mode):
    proxy_block = build_proxy_block(node)
    node_name = node["name"]

    # ===== 头部 =====
    head = """port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: :9090
unified-delay: true
tcp-concurrent: true

dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
"""

    # ===== 节点 =====
    proxies_section = f"""
proxies:
{proxy_block}
"""

    # ===== 策略组 =====
    groups_section = f"""
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - "{node_name}"
      - DIRECT

  - name: 🐟 漏网之鱼
    type: select
    proxies:
      - 🚀 节点选择
      - DIRECT
"""

    # ===== 规则 =====
    if rule_mode == "1":
        rules_section = """
rule-providers:
  reject:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt"
    path: ./ruleset/reject.yaml
    interval: 86400
  icloud:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt"
    path: ./ruleset/icloud.yaml
    interval: 86400
  apple:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt"
    path: ./ruleset/apple.yaml
    interval: 86400
  google:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt"
    path: ./ruleset/google.yaml
    interval: 86400
  proxy:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
    path: ./ruleset/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"
    path: ./ruleset/direct.yaml
    interval: 86400
  cncidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"
    path: ./ruleset/cncidr.yaml
    interval: 86400
  lancidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt"
    path: ./ruleset/lancidr.yaml
    interval: 86400

rules:
  - RULE-SET,reject,REJECT
  - RULE-SET,icloud,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,google,🚀 节点选择
  - RULE-SET,proxy,🚀 节点选择
  - RULE-SET,direct,DIRECT
  - RULE-SET,lancidr,DIRECT
  - RULE-SET,cncidr,DIRECT
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🐟 漏网之鱼
"""
    else:
        rules_section = """
rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - DOMAIN-SUFFIX,cn,DIRECT
  - MATCH,🚀 节点选择
"""

    return head + proxies_section + groups_section + rules_section


def main():
    banner()

    while True:
        vless_url = input("\n[1/3] 请输入 VLESS 链接: ").strip()
        if not vless_url:
            continue
        node_data, error = parse_vless(vless_url)
        if error:
            print(f"❌ {error}")
        else:
            print(f"✅ 成功识别: {node_data['name']} [{node_data['type'].upper()}]")
            break

    print("\n[2/3] 请选择规则模式：")
    print("   1. 在线增强版 (推荐)")
    print("   2. 本地精简版 (稳)")

    while True:
        mode = input("👉 请输入数字 (1 或 2): ").strip()
        if mode in ["1", "2"]:
            break
        print("❌ 输入错误，请输入 1 或 2")

    filename = input("\n[3/3] 请输入文件名 (默认 config.yaml): ").strip()
    if not filename:
        filename = "config.yaml"
    if not filename.endswith(".yaml"):
        filename += ".yaml"

    try:
        content = generate_content(node_data, mode)

        # 写入前先打印预览，方便排错
        print("\n--- 生成预览(前30行) ---")
        preview_lines = content.strip().split('\n')[:30]
        for line in preview_lines:
            print(line)
        print("... (省略)")
        print("--- 预览结束 ---\n")

        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)

        print("=" * 40)
        print(f"🎉 成功！文件已生成: {os.path.abspath(filename)}")
        print("=" * 40)
    except Exception as e:
        print(f"❌ 写入文件失败: {e}")

    input("\n按回车键退出...")


if __name__ == "__main__":
    main()
