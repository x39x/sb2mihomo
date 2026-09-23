import json
from argparse import ArgumentParser

import yaml

#####################################
# converter
#####################################


def anytls(clash):
    singbox = {}
    singbox["type"] = clash["type"]
    singbox["tag"] = clash["name"]
    singbox["server"] = clash["server"]
    singbox["server_port"] = clash["port"]
    singbox["password"] = clash["password"]
    singbox["tls"] = {
        "enabled": True,
        "server_name": clash["sni"],
        "insecure": True,
        "alpn": clash["alpn"],
        "utls": {"enabled": True, "fingerprint": clash["client-fingerprint"]},
    }
    return singbox


def vless(clash):
    singbox = {}
    singbox["type"] = clash["type"]
    singbox["tag"] = clash["name"]
    singbox["server"] = clash["server"]
    singbox["server_port"] = clash["port"]
    singbox["uuid"] = clash["uuid"]
    singbox["flow"] = clash["flow"]
    singbox["tls"] = {
        "enabled": clash["tls"],
        "server_name": clash["servername"],
        "utls": {
            "enabled": True,
            "fingerprint": clash["client-fingerprint"],
        },
        "reality": {
            "enabled": True,
            "public_key": clash["reality-opts"]["public-key"],
            "short_id": clash["reality-opts"]["short-id"],
        },
    }
    return singbox


def trojan(clash):
    singbox = {}
    singbox["type"] = clash["type"]
    singbox["tag"] = clash["name"]
    singbox["server"] = clash["server"]
    singbox["server_port"] = clash["port"]
    singbox["password"] = clash["password"]
    singbox["tls"] = {
        "enabled": True,
        "server_name": clash["sni"],
        "insecure": True,
    }
    return singbox


CONVERTERS = {
    "vless": vless,
    "trojan": trojan,
    "anytls": anytls,
}

#####################################
# clash -> singbox
#####################################


def parse_proxies(path):
    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    proxies = []
    for proxy in config["proxies"]:
        if proxy["type"] == "mieru":
            print("skip mieru")
            continue
        try:
            # TODO:
            proxies.append(CONVERTERS[proxy["type"]](proxy))
        except KeyError:
            raise ValueError(f"unsupported proxy type: {proxy['type']}")
    return proxies


def parse_args():
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", nargs="+", required=True, help="yaml file")
    return parser.parse_args()


def make_singbox_config(proxies, tags):
    with open("./template.json", encoding="utf-8", mode="r") as f:
        template = json.load(f)
    for i, outbound in enumerate(template["outbounds"]):
        if outbound["tag"] in ["cuckoo", "godwit", "gull", "urltest"]:
            template["outbounds"][i]["outbounds"] += tags
    template["outbounds"] += proxies
    return template


def main(files):
    proxies = [proxy for file in files for proxy in parse_proxies(file)]
    tags = [p["tag"] for p in proxies]
    singbox_config = make_singbox_config(proxies, tags)
    with open("config.json", mode="w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    # main(["./data/proxy_1.yaml", "./data/proxy_2.yaml", "./data/dog.yaml"])
    args = parse_args()
    main(args.file)
