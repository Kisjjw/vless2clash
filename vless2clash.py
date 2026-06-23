import json
import os
import ipaddress
import re
import urllib.parse


def quote(value):
    return json.dumps(str(value), ensure_ascii=False)


def bool_value(value):
    return "true" if value else "false"


def first(params, *keys, default=""):
    for key in keys:
        values = params.get(key)
        if values:
            return values[0]
    return default


def split_list(value):
    if not value:
        return []
    return [item.strip() for item in value.replace("|", ",").split(",") if item.strip()]


def parse_bool(value, default=False):
    if value is None or value == "":
        return default
    return str(value).lower() in {"1", "true", "yes", "on"}


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def banner():
    print("=" * 66)
    print("Mihomo / Clash.Meta 多订阅合并配置生成器")
    print("=" * 66)
    print("支持输入：")
    print("1. http/https 订阅链接，生成 proxy-providers 自动更新配置")
    print("2. vless:// 或 tuic:// 单条分享链接，直接写入 proxies")
    print("3. 数量不限，逐条粘贴，输入空行结束")
    print("4. 订阅可用 名称=链接，例如 tuic=https://example/sub")
    print("=" * 66)


def parse_vless(url):
    parsed = urllib.parse.urlparse(url.strip())
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if parsed.scheme != "vless":
        raise ValueError("不是 vless:// 链接")
    if not parsed.username or not parsed.hostname or not parsed.port:
        raise ValueError("VLESS 链接缺少 uuid、server 或 port")

    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "vless-reality"
    security = first(params, "security", default="")
    network = first(params, "type", default="tcp")
    sni = first(params, "sni", "servername", "serverName", default=parsed.hostname)
    fingerprint = first(params, "fp", "fingerprint", default="chrome")

    node = {
        "name": name,
        "type": "vless",
        "server": parsed.hostname,
        "port": parsed.port,
        "uuid": urllib.parse.unquote(parsed.username),
        "udp": True,
        "network": network,
    }

    if security == "reality":
        public_key = first(params, "pbk", "publicKey", "public-key")
        short_id = first(params, "sid", "shortId", "short-id")
        if not public_key:
            raise ValueError("VLESS REALITY 链接缺少 pbk/public-key")

        node.update(
            {
                "tls": True,
                "flow": first(params, "flow", default="xtls-rprx-vision"),
                "servername": sni,
                "client-fingerprint": fingerprint,
                "reality-opts": {
                    "public-key": public_key,
                    "short-id": short_id,
                },
                "smux": {"enabled": False},
            }
        )
        spider_x = first(params, "spx", "spiderX")
        if spider_x:
            node["reality-opts"]["spider-x"] = spider_x
    elif network == "ws":
        host = first(params, "host", default=sni or parsed.hostname)
        path = urllib.parse.unquote(first(params, "path", default="/"))
        node.update(
            {
                "tls": security == "tls" or parsed.port == 443,
                "servername": sni,
                "client-fingerprint": fingerprint,
                "ws-opts": {
                    "path": path,
                    "headers": {"Host": host},
                },
            }
        )
    else:
        node.update(
            {
                "network": "tcp",
                "tls": security in {"tls", "reality"} or parsed.port == 443,
                "servername": sni,
                "client-fingerprint": fingerprint,
            }
        )

    return node


def parse_tuic(url):
    parsed = urllib.parse.urlparse(url.strip())
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if parsed.scheme != "tuic":
        raise ValueError("不是 tuic:// 链接")
    if not parsed.hostname or not parsed.port:
        raise ValueError("TUIC 链接缺少 server 或 port")

    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "tuic"
    username = urllib.parse.unquote(parsed.username or first(params, "uuid"))
    password = urllib.parse.unquote(parsed.password or first(params, "password"))
    if username and not password and ":" in username:
        username, password = username.split(":", 1)
    if not username or not password:
        raise ValueError("TUIC 链接缺少 uuid 或 password")

    node = {
        "name": name,
        "type": "tuic",
        "server": parsed.hostname,
        "port": parsed.port,
        "uuid": username,
        "password": password,
        "udp": True,
    }

    sni = first(params, "sni", "servername", "serverName")
    if sni:
        node["sni"] = sni

    alpn = split_list(first(params, "alpn"))
    if alpn:
        node["alpn"] = alpn

    congestion = first(params, "congestion_control", "congestion-controller", default="bbr")
    if congestion:
        node["congestion-controller"] = congestion

    udp_mode = first(params, "udp_relay_mode", "udp-relay-mode", default="native")
    if udp_mode:
        node["udp-relay-mode"] = udp_mode

    reduce_rtt = first(params, "reduce_rtt", "reduce-rtt")
    if reduce_rtt:
        node["reduce-rtt"] = parse_bool(reduce_rtt)

    insecure = first(
        params,
        "allow_insecure",
        "allowInsecure",
        "allow-insecure",
        "skip-cert-verify",
        "skip_cert_verify",
        "insecure",
    )
    if insecure:
        node["skip-cert-verify"] = parse_bool(insecure)
    elif sni and is_ip_address(parsed.hostname):
        node["skip-cert-verify"] = True

    return node


def normalize_provider_name(name, fallback):
    value = re.sub(r"[^A-Za-z0-9_-]+", "-", name.strip())
    value = value.strip("-_")
    return value or fallback


def unique_name(name, used_names):
    if name not in used_names:
        used_names.add(name)
        return name

    index = 2
    while f"{name}-{index}" in used_names:
        index += 1
    final_name = f"{name}-{index}"
    used_names.add(final_name)
    return final_name


def split_named_source(raw):
    value = raw.strip()
    for scheme in ("https://", "http://", "vless://", "tuic://"):
        marker = f"={scheme}"
        if marker in value:
            name, link = value.split("=", 1)
            return name.strip(), link.strip()
    return "", value


def guess_provider_name(url, index):
    lower = url.lower()
    if "tuic" in lower:
        return "tuic"
    if "vless" in lower or "reality" in lower:
        return "vless"
    return f"provider-{index}"


def parse_source(raw, index, used_provider_names, used_node_names):
    display_name, value = split_named_source(raw)
    lower = value.lower()

    if lower.startswith("http://") or lower.startswith("https://"):
        fallback_name = guess_provider_name(value, index)
        provider_name = normalize_provider_name(display_name, fallback_name)
        provider_name = unique_name(provider_name, used_provider_names)
        return {
            "kind": "provider",
            "name": provider_name,
            "url": value,
        }
    if lower.startswith("vless://"):
        node = parse_vless(value)
        if display_name:
            node["name"] = display_name
        node["name"] = unique_name(node["name"], used_node_names)
        return {
            "kind": "proxy",
            "node": node,
        }
    if lower.startswith("tuic://"):
        node = parse_tuic(value)
        if display_name:
            node["name"] = display_name
        node["name"] = unique_name(node["name"], used_node_names)
        return {
            "kind": "proxy",
            "node": node,
        }

    raise ValueError("只支持 http(s) 订阅链接、vless:// 或 tuic://")


def emit_value(lines, key, value, indent):
    prefix = " " * indent
    if isinstance(value, bool):
        lines.append(f"{prefix}{key}: {bool_value(value)}")
    elif isinstance(value, int):
        lines.append(f"{prefix}{key}: {value}")
    elif isinstance(value, list):
        lines.append(f"{prefix}{key}:")
        for item in value:
            lines.append(f"{prefix}  - {quote(item)}")
    elif isinstance(value, dict):
        lines.append(f"{prefix}{key}:")
        for child_key, child_value in value.items():
            emit_value(lines, child_key, child_value, indent + 2)
    else:
        lines.append(f"{prefix}{key}: {quote(value)}")


def build_proxy_yaml(node):
    lines = []
    lines.append(f"  - name: {quote(node['name'])}")
    for key, value in node.items():
        if key == "name":
            continue
        emit_value(lines, key, value, 4)
    return "\n".join(lines)


def build_provider_yaml(source):
    name = source["name"]
    provider_type = "vless" if "vless" in name.lower() else "tuic"
    lines = [
        f"  {name}:",
        "    type: http",
        f"    url: {quote(source['url'])}",
        f"    path: ./proxy_providers/{name}.yaml",
        "    interval: 3600",
        "    health-check:",
        "      enable: true",
        "      url: https://www.gstatic.com/generate_204",
        "      interval: 300",
        "      timeout: 5000",
        "    override:",
        "      udp: true",
    ]
    if provider_type == "vless":
        lines.extend(
            [
                "      smux:",
                "        enabled: false",
            ]
        )
    return "\n".join(lines)


def build_config(sources, rule_mode):
    provider_sources = [item for item in sources if item["kind"] == "provider"]
    proxy_sources = [item for item in sources if item["kind"] == "proxy"]
    proxy_names = [item["node"]["name"] for item in proxy_sources]
    provider_names = [item["name"] for item in provider_sources]
    direct_proxy_names = proxy_names + ["DIRECT"]

    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "ipv6: true",
        "unified-delay: true",
        "tcp-concurrent: true",
        "",
        "dns:",
        "  enable: true",
        "  enhanced-mode: redir-host",
        "  nameserver:",
        "    - 223.5.5.5",
        "    - 119.29.29.29",
        "",
    ]

    if provider_sources:
        lines.append("proxy-providers:")
        for source in provider_sources:
            lines.append(build_provider_yaml(source))
        lines.append("")

    if proxy_sources:
        lines.append("proxies:")
        for source in proxy_sources:
            lines.append(build_proxy_yaml(source["node"]))
        lines.append("")

    lines.extend(
        [
            "proxy-groups:",
            "  - name: 节点选择",
            "    type: select",
            "    proxies:",
            "      - TUIC优先",
            "      - 自动测速",
            "      - 故障切换",
        ]
    )
    for name in direct_proxy_names:
        lines.append(f"      - {quote(name)}" if name != "DIRECT" else "      - DIRECT")
    if provider_names:
        lines.append("    use:")
        for name in provider_names:
            lines.append(f"      - {name}")

    for group_name, group_type in [
        ("TUIC优先", "fallback"),
        ("自动测速", "url-test"),
        ("故障切换", "fallback"),
    ]:
        lines.extend(
            [
                "",
                f"  - name: {group_name}",
                f"    type: {group_type}",
            ]
        )
        if group_name == "TUIC优先":
            ordered_proxy_names = sorted(
                proxy_names,
                key=lambda item: 0 if "tuic" in item.lower() else 1,
            )
        else:
            ordered_proxy_names = proxy_names

        if ordered_proxy_names:
            lines.append("    proxies:")
            for name in ordered_proxy_names:
                lines.append(f"      - {quote(name)}")

        if provider_names:
            lines.append("    use:")
            ordered_provider_names = sorted(
                provider_names,
                key=lambda item: 0 if "tuic" in item.lower() else 1,
            ) if group_name == "TUIC优先" else provider_names
            for name in ordered_provider_names:
                lines.append(f"      - {name}")

        lines.extend(
            [
                "    url: https://www.gstatic.com/generate_204",
                "    interval: 300",
            ]
        )
        if group_type == "url-test":
            lines.append("    tolerance: 50")

    lines.append("")
    if rule_mode == "1":
        lines.extend(build_rules_with_providers())
    else:
        lines.extend(
            [
                "rules:",
                *build_mobile_direct_rules(),
                "  - GEOIP,LAN,DIRECT",
                "  - GEOIP,CN,DIRECT",
                "  - DOMAIN-SUFFIX,cn,DIRECT",
                "  - MATCH,节点选择",
            ]
        )

    return "\n".join(lines) + "\n"


def build_mobile_direct_rules():
    return [
        "  - DOMAIN-SUFFIX,qq.com,DIRECT",
        "  - DOMAIN-SUFFIX,qlogo.cn,DIRECT",
        "  - DOMAIN-SUFFIX,qpic.cn,DIRECT",
        "  - DOMAIN-SUFFIX,gtimg.cn,DIRECT",
        "  - DOMAIN-SUFFIX,idqqimg.com,DIRECT",
        "  - DOMAIN-SUFFIX,tencent.com,DIRECT",
        "  - DOMAIN-SUFFIX,myqcloud.com,DIRECT",
        "  - DOMAIN-SUFFIX,weixin.qq.com,DIRECT",
        "  - DOMAIN-SUFFIX,tenpay.com,DIRECT",
        "  - DOMAIN-SUFFIX,douyin.com,DIRECT",
        "  - DOMAIN-SUFFIX,douyincdn.com,DIRECT",
        "  - DOMAIN-SUFFIX,douyinpic.com,DIRECT",
        "  - DOMAIN-SUFFIX,douyinstatic.com,DIRECT",
        "  - DOMAIN-SUFFIX,amemv.com,DIRECT",
        "  - DOMAIN-SUFFIX,snssdk.com,DIRECT",
        "  - DOMAIN-SUFFIX,toutiao.com,DIRECT",
        "  - DOMAIN-SUFFIX,toutiaoapi.com,DIRECT",
        "  - DOMAIN-SUFFIX,ixigua.com,DIRECT",
        "  - DOMAIN-SUFFIX,ixgvideo.com,DIRECT",
        "  - DOMAIN-SUFFIX,byteimg.com,DIRECT",
        "  - DOMAIN-SUFFIX,bytedance.com,DIRECT",
        "  - DOMAIN-SUFFIX,bytedance.net,DIRECT",
        "  - DOMAIN-SUFFIX,pstatp.com,DIRECT",
        "  - DOMAIN-SUFFIX,zijieapi.com,DIRECT",
        "  - DOMAIN-KEYWORD,douyin,DIRECT",
    ]


def build_rules_with_providers():
    return [
        "rule-providers:",
        "  reject:",
        "    type: http",
        "    behavior: domain",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt"',
        "    path: ./ruleset/reject.yaml",
        "    interval: 86400",
        "  private:",
        "    type: http",
        "    behavior: domain",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt"',
        "    path: ./ruleset/private.yaml",
        "    interval: 86400",
        "  icloud:",
        "    type: http",
        "    behavior: domain",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt"',
        "    path: ./ruleset/icloud.yaml",
        "    interval: 86400",
        "  apple:",
        "    type: http",
        "    behavior: domain",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt"',
        "    path: ./ruleset/apple.yaml",
        "    interval: 86400",
        "  google:",
        "    type: http",
        "    behavior: domain",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt"',
        "    path: ./ruleset/google.yaml",
        "    interval: 86400",
        "  proxy:",
        "    type: http",
        "    behavior: domain",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"',
        "    path: ./ruleset/proxy.yaml",
        "    interval: 86400",
        "  direct:",
        "    type: http",
        "    behavior: domain",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"',
        "    path: ./ruleset/direct.yaml",
        "    interval: 86400",
        "  applications:",
        "    type: http",
        "    behavior: classical",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt"',
        "    path: ./ruleset/applications.yaml",
        "    interval: 86400",
        "  telegramcidr:",
        "    type: http",
        "    behavior: ipcidr",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt"',
        "    path: ./ruleset/telegramcidr.yaml",
        "    interval: 86400",
        "  cncidr:",
        "    type: http",
        "    behavior: ipcidr",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"',
        "    path: ./ruleset/cncidr.yaml",
        "    interval: 86400",
        "  lancidr:",
        "    type: http",
        "    behavior: ipcidr",
        '    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt"',
        "    path: ./ruleset/lancidr.yaml",
        "    interval: 86400",
        "",
        "rules:",
        *build_mobile_direct_rules(),
        "  - RULE-SET,applications,DIRECT",
        "  - RULE-SET,private,DIRECT",
        "  - RULE-SET,reject,REJECT",
        "  - RULE-SET,icloud,DIRECT",
        "  - RULE-SET,apple,DIRECT",
        "  - RULE-SET,google,节点选择",
        "  - RULE-SET,proxy,节点选择",
        "  - RULE-SET,direct,DIRECT",
        "  - RULE-SET,lancidr,DIRECT,no-resolve",
        "  - RULE-SET,cncidr,DIRECT,no-resolve",
        "  - RULE-SET,telegramcidr,节点选择,no-resolve",
        "  - GEOIP,LAN,DIRECT,no-resolve",
        "  - GEOIP,CN,DIRECT,no-resolve",
        "  - MATCH,节点选择",
    ]


def ask_sources():
    print("\n逐条输入订阅或分享链接，输入空行结束。")
    print("示例：")
    print("  https://example.com/sub")
    print("  tuic=https://example.com/tuic-sub")
    print("  vless://...")
    print("  tuic://...")

    sources = []
    used_provider_names = set()
    used_node_names = set()
    while True:
        raw = input(f"\n链接 #{len(sources) + 1}：").strip()
        if not raw:
            if sources:
                return sources
            print("至少需要输入一条链接。")
            continue

        try:
            source = parse_source(
                raw,
                len(sources) + 1,
                used_provider_names,
                used_node_names,
            )
        except Exception as exc:
            print(f"解析失败：{exc}")
            continue

        sources.append(source)
        if source["kind"] == "provider":
            print(f"已添加订阅 provider：{source['name']}")
        else:
            node = source["node"]
            print(f"已添加节点：{node['name']} [{node['type']}]")

def ask_rule_mode():
    print("\n请选择规则模式：")
    print("1. 在线规则集，适合日常使用")
    print("2. 本地简易规则，配置更短")
    while True:
        mode = input("请输入 1 或 2：").strip()
        if mode in {"1", "2"}:
            return mode
        print("输入错误，请输入 1 或 2。")


def main():
    banner()
    sources = ask_sources()
    rule_mode = ask_rule_mode()

    filename = input("\n输出文件名，默认 config.yaml：").strip() or "config.yaml"
    if not filename.endswith((".yaml", ".yml")):
        filename += ".yaml"

    content = build_config(sources, rule_mode)
    with open(filename, "w", encoding="utf-8") as file:
        file.write(content)

    print("\n生成完成：")
    print(os.path.abspath(filename))
    print("\n前 40 行预览：")
    print("-" * 66)
    for line in content.splitlines()[:40]:
        print(line)
    print("-" * 66)


if __name__ == "__main__":
    main()
