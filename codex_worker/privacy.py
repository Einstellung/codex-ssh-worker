import ipaddress
import json
import re
import unicodedata


# Exactly four dotted parts. A sentence-ending period is allowed, a fifth
# numeric part is not: "1.2.3.4.5" is a version, never an address.
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?!\w|\.\d)")
# Text immediately before a four-part number that marks it as a software
# version (pip pins, driver/CUDA banners). Kept narrow on purpose: an
# unmarked four-part number that is a valid address is still redacted.
VERSION_CONTEXT = re.compile(
    r"(?i)(?:[=<>!~]=\s*|\b(?:v|ver|version|cuda|cudnn|driver|nvidia|firmware|toolkit)[\s:=_-]*)$")
IPV6 = re.compile(r"(?<![\w:])(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9:.]*(?:%[\w.-]+)?(?:/\d{1,3})?")
# Hostnames are recognised only by a known public or private-network suffix,
# so filenames (train.py, pilot.tar) and code (os.path) are left alone. Bare
# private names belong in the policy's sensitive_literals.
HOST_SUFFIXES = frozenset("""
com net org io cn edu gov mil int dev ai app cloud co me info biz tech xyz site online
uk de jp kr fr ru eu us ca au in hk tw sg
local localdomain internal intranet lan home corp private test example invalid localhost
""".split())
FILE_EXTENSIONS = frozenset("""
txt py sh json md csv tsv tar gz tgz bz2 xz zst zip 7z rar log yaml yml toml ini cfg conf
jpg jpeg png gif bmp tif tiff webp heic mp4 mov avi pt pth ckpt onnx bin safetensors h5 npy npz
pkl pickle parquet whl so dll exe html htm xml pdf docx xlsx ipynb lock out err tmp bak
""".split())


def host_pattern(suffixes=HOST_SUFFIXES):
    allowed = sorted({s.casefold().lstrip(".") for s in suffixes} - FILE_EXTENSIONS, key=len, reverse=True)
    return re.compile(r"(?i)(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:"
                      + "|".join(map(re.escape, allowed)) + r")(?![\w-]|\.\w)")


HOST = host_pattern()
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
SECRETS = re.compile(r"(?i)\b(password|passwd|api[_-]?key|access[_-]?token|secret|authorization)\s*[:=]\s*[^\s,;]+")
URI_AUTH = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]{0,63}://)[^\s/@]+(?::[^\s/@]*)?@")
GEO = re.compile(r"(?i)\b(?:cn-(?:north|south|east|west|central)[a-z0-9-]*|mainland\s+china|china|beijing|shanghai|chengdu|sichuan)\b|中国大陆|中国境内|中国|北京|上海|成都|四川|宜宾")
SENSITIVE_KEY = re.compile(r"(?i)(?:^|_)(?:ip|ipv4|ipv6|host|hostname|endpoint|domain|country|city|province|region|location|timezone|latitude|longitude|coordinates|username|account|password|passwd|secret|credential|authorization|token|api_key)(?:_|$)|地址|位置|地域|地区|经纬度|密码|密钥|主机名")


class Redactor:
    def __init__(self, literals=(), host_suffixes=()):
        self.host = host_pattern(HOST_SUFFIXES | set(host_suffixes)) if host_suffixes else HOST
        self.literals = sorted({str(value) for value in literals if value and len(str(value)) >= 3}, key=len, reverse=True)
        self.aliases = {}

    def alias(self, category, value):
        key = (category, value.casefold())
        if key not in self.aliases:
            self.aliases[key] = f"[redacted-{category}-{len(self.aliases) + 1}]"
        return self.aliases[key]

    def address(self, match):
        value = match.group().rstrip(".")
        if "." in value and ":" not in value and VERSION_CONTEXT.search(match.string[max(0, match.start() - 24):match.start()]):
            return match.group()
        try:
            if "/" in value:
                ipaddress.ip_network(value, strict=False)
            else:
                ipaddress.ip_address(value)
        except ValueError:
            return match.group()
        return self.alias("address", value) + match.group()[len(value):]

    def text(self, value):
        value = unicodedata.normalize("NFKC", ANSI.sub("", value))
        value = "".join(character for character in value if character in "\n\r\t" or not unicodedata.category(character).startswith("C"))
        value = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[redacted-private-key]", value, flags=re.S)
        for literal in self.literals:
            value = re.sub(re.escape(literal), lambda match: self.alias("private", match.group()), value, flags=re.I)
        value = URI_AUTH.sub(r"\1[redacted-credentials]@", value)
        value = SECRETS.sub(lambda match: match.group(1) + "=[redacted-secret]", value)
        value = IPV6.sub(self.address, value)
        value = IPV4.sub(self.address, value)
        value = GEO.sub(lambda match: self.alias("location", match.group()), value)
        value = self.host.sub(lambda match: self.alias("hostname", match.group()), value)
        return value

    def clean(self, value, depth=0):
        if depth > 64:
            raise ValueError("report nesting limit")
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                key = str(key)
                normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).replace("-", "_")
                safe_key = self.text(key)
                if safe_key in result:
                    safe_key = f"redacted_field_{len(result)}"
                result[safe_key] = "[redacted-field]" if SENSITIVE_KEY.search(normalized) else self.clean(item, depth + 1)
            return result
        if isinstance(value, (list, tuple)):
            return [self.clean(item, depth + 1) for item in value]
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith(("{", "[")):
                try:
                    nested = json.loads(stripped)
                except (ValueError, RecursionError):
                    pass
                else:
                    return json.dumps(self.clean(nested, depth + 1), ensure_ascii=False, allow_nan=False)
            return self.text(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        raise ValueError("unsupported report value")


def make_redactor(settings, credentials, policy, private):
    literals = list(policy.get("sensitive_literals", [])) + [str(private)]
    for resource in settings["resources"].values():
        literals.extend(resource.get(key) for key in ("host", "bind_address", "private_hostname", "private_home"))
    for credential in credentials.values():
        literals.extend(credential.values())
    return Redactor(literals, policy.get("hostname_suffixes", ()))
