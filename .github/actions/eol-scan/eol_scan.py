#!/usr/bin/env python3
"""Detect runtime and framework components in a repository and evaluate them
against https://endoflife.date.

The scanner is deliberately conservative. It only reports a component when it
can tie a concrete version to a product that endoflife.date actually tracks,
and it only lets a *pinned* version fail a build. A version that comes from an
open-ended range (``>=18``) is recorded as advisory, because the range says
nothing about what is really installed.

Standard library only, so it runs on a bare runner with no install step.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, NamedTuple

API_ROOT = "https://endoflife.date/api/v1"
USER_AGENT = "catch-shared-workflows-eol-scan/1 (+https://github.com/catch-oss/shared-workflows)"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
    "target", ".terraform", "bower_components", "coverage", ".yarn",
    ".pnpm-store", ".gradle", ".idea", ".vscode", "storage",
    ".serverless", ".turbo", ".parcel-cache", "tmp",
}
MAX_FILES = 40000

# --------------------------------------------------------------------------
# Product maps. Every mapped name is checked against the live endoflife.date
# product index before it is reported, so a stale or wrong entry here degrades
# to "not detected" rather than to a false finding.
# --------------------------------------------------------------------------

DOCKER_PRODUCTS = {
    "node": "nodejs", "python": "python", "php": "php", "ruby": "ruby",
    "golang": "go", "go": "go", "rust": "rust", "perl": "perl", "elixir": "elixir",
    "openjdk": "eclipse-temurin", "eclipse-temurin": "eclipse-temurin",
    "ibm-semeru-runtimes": "eclipse-temurin", "azul/zulu-openjdk": "azul-zulu",
    "amazoncorretto": "amazon-corretto", "gradle": "gradle", "maven": "maven",
    "postgres": "postgresql", "mysql": "mysql", "mariadb": "mariadb",
    "redis": "redis", "valkey": "valkey", "mongo": "mongodb",
    "elasticsearch": "elasticsearch", "kibana": "kibana", "logstash": "logstash",
    "influxdb": "influxdb", "neo4j": "neo4j", "couchdb": "apache-couchdb",
    "cassandra": "apache-cassandra", "zookeeper": "apache-zookeeper",
    "solr": "apache-solr", "memcached": "memcached", "rabbitmq": "rabbitmq",
    "nginx": "nginx", "httpd": "apache-http-server", "haproxy": "haproxy",
    "varnish": "varnish", "traefik": "traefik", "caddy": "caddy",
    "consul": "consul", "vault": "hashicorp-vault", "nats": "nats-server",
    "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine",
    "centos": "centos", "rockylinux": "rocky-linux", "almalinux": "almalinux",
    "fedora": "fedora", "amazonlinux": "amazon-linux", "oraclelinux": "oracle-linux",
    "opensuse/leap": "opensuse", "wordpress": "wordpress", "drupal": "drupal",
    "joomla": "joomla", "nextcloud": "nextcloud", "sonarqube": "sonarqube",
    "grafana/grafana": "grafana", "jenkins/jenkins": "jenkins",
    "kong": "kong-gateway",
    "opensearchproject/opensearch": "opensearch",
    "mcr.microsoft.com/dotnet/aspnet": "dotnet",
    "mcr.microsoft.com/dotnet/runtime": "dotnet",
    "mcr.microsoft.com/dotnet/sdk": "dotnet",
    "mcr.microsoft.com/mssql/server": "mssqlserver",
}

# Package name -> endoflife.date product, per ecosystem.
NPM_PRODUCTS = {
    "next": "nextjs", "nuxt": "nuxt", "@angular/core": "angular",
    "@angular/cli": "angular", "vue": "vue", "react": "react",
    "express": "express", "electron": "electron", "svelte": "svelte",
}
COMPOSER_PRODUCTS = {
    "php": "php", "laravel/framework": "laravel", "symfony/symfony": "symfony",
    "symfony/framework-bundle": "symfony", "drupal/core": "drupal",
    "drupal/core-recommended": "drupal", "typo3/cms-core": "typo3",
    "silverstripe/framework": "silverstripe", "silverstripe/recipe-cms": "silverstripe",
    "craftcms/cms": "craft-cms", "shopware/core": "shopware",
    "contao/core-bundle": "contao",
    "magento/product-community-edition": "magento", "roots/wordpress": "wordpress",
    "johnpbloch/wordpress": "wordpress", "cakephp/cakephp": "cakephp",
}
PYPI_PRODUCTS = {
    "django": "django", "numpy": "numpy",
    "ansible": "ansible", "ansible-core": "ansible-core",
}
GEM_PRODUCTS = {"rails": "rails"}

# `.tool-versions` / mise / asdf plugin name -> product.
TOOL_PRODUCTS = {
    "nodejs": "nodejs", "node": "nodejs", "python": "python", "ruby": "ruby",
    "php": "php", "golang": "go", "go": "go", "rust": "rust",
    "terraform": "terraform", "deno": "deno", "bun": "bun", "elixir": "elixir",
    "erlang": "erlang", "postgres": "postgresql", "dotnet": "dotnet",
    "dotnet-core": "dotnet", "kubectl": "kubernetes",
}

# endoflife.date tracks JDK *distributions*, not a generic "java" product.
# A bare version is attributed to Temurin, the de facto OpenJDK build.
JAVA_DISTRIBUTIONS = {
    "temurin": "eclipse-temurin", "adoptopenjdk": "eclipse-temurin",
    "corretto": "amazon-corretto", "zulu": "azul-zulu",
    "oracle": "oracle-jdk", "graalvm": "graalvm", "openjdk": "eclipse-temurin",
    "semeru": "eclipse-temurin", "liberica": "eclipse-temurin",
}
DEFAULT_JAVA_DISTRIBUTION = "eclipse-temurin"

# `runtime:` identifiers used by Lambda / App Engine / Cloud Functions.
CLOUD_RUNTIME = re.compile(
    r"^(?P<name>nodejs|python|ruby|java|dotnet|dotnetcore|go|php)"
    r"(?P<ver>\d+(?:[._]\d+)*)?(?:\.x)?$",
    re.IGNORECASE,
)
CLOUD_RUNTIME_PRODUCTS = {
    "nodejs": "nodejs", "python": "python", "ruby": "ruby",
    "java": "eclipse-temurin", "dotnet": "dotnet", "dotnetcore": "dotnet",
    "go": "go", "php": "php",
}

# Tags that carry no resolvable version.
UNRESOLVABLE_TAGS = {
    "latest", "stable", "main", "master", "edge", "nightly", "dev", "current",
    "lts", "alpine", "slim", "bookworm", "bullseye", "buster", "trixie",
}


class Detection(NamedTuple):
    product: str
    version: str
    source: str
    locked: int  # leading version components the declaration guarantees


# --------------------------------------------------------------------------
# Version parsing
# --------------------------------------------------------------------------

_CONSTRAINT = re.compile(
    r"^\s*(?P<op>>=|<=|>|<|~>|\^|~|==|=|v)?\s*(?P<ver>\d+(?:\.\d+)*)"
)

def locked_components(op, version: str) -> int:
    """How many leading version components a constraint actually guarantees.

    This is what separates a finding that may fail a build from one that can
    only warn. `"php": "^8.1"` permits 8.5, so it locks the major only, while
    a `.nvmrc` holding `20.11.1` locks every component.
    """
    depth = len(version.split("."))
    if op in {">=", ">"}:
        return 0
    if op == "^":
        # Semver caret: `^0.2.3` is bounded at the minor, `^8.1` at the major.
        return min(2, depth) if version.startswith("0.") else 1
    if op == "~":
        return min(2, depth)
    if op == "~>":  # Ruby / Terraform pessimistic operator
        return max(1, depth - 1)
    return depth


def exact(version: str) -> int:
    """A literal version locks every component it states."""
    return len(version.split("."))


def parse_constraint(raw: object) -> tuple[str | None, int | None]:
    """Turn a version declaration into ``(version, locked_components)``."""
    if raw is None:
        return None, None
    text = str(raw).strip().strip("\"'")
    if not text or text.lower() in UNRESOLVABLE_TAGS or text in {"*", "x", "X"}:
        return None, None
    # Take the first clause of a compound range: ">=8.1 <9" or "^7 || ^8".
    first = re.split(r"\|\||,|\s+-\s+", text)[0].strip()
    match = _CONSTRAINT.match(first)
    if not match:
        return None, None
    op = match.group("op")
    if op in {"<", "<="}:
        return None, None
    version = match.group("ver")
    return version, locked_components(op, version)


def docker_tag_version(tag: str) -> str | None:
    """`8.2-fpm-alpine` -> `8.2`; `lts-alpine` -> None."""
    if not tag or tag.lower() in UNRESOLVABLE_TAGS:
        return None
    match = re.match(r"^v?(\d+(?:\.\d+)*)", tag)
    return match.group(1) if match else None


def split_image(image: str) -> tuple[str, str] | None:
    """Split `docker.io/library/node:20-alpine` into (`node`, `20-alpine`)."""
    ref = image.strip()
    if not ref or "$" in ref.split(":")[0]:
        return None
    ref = ref.split("@", 1)[0]  # drop any digest
    if ":" not in ref.rsplit("/", 1)[-1]:
        return None
    name, tag = ref.rsplit(":", 1)
    for prefix in ("docker.io/library/", "docker.io/", "index.docker.io/library/",
                   "index.docker.io/", "public.ecr.aws/docker/library/", "library/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name, tag


def docker_product(name: str) -> str | None:
    lowered = name.lower()
    if lowered in DOCKER_PRODUCTS:
        return DOCKER_PRODUCTS[lowered]
    return DOCKER_PRODUCTS.get(lowered.rsplit("/", 1)[-1])


# --------------------------------------------------------------------------
# File walking
# --------------------------------------------------------------------------

def iter_files(root: Path) -> Iterable[Path]:
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            seen += 1
            if seen > MAX_FILES:
                return
            yield Path(dirpath) / filename


def read_text(path: Path, limit: int = 512_000) -> str:
    try:
        if path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_json(path: Path) -> dict:
    try:
        value = json.loads(read_text(path) or "{}")
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


# --------------------------------------------------------------------------
# Detectors. Each returns Detection objects; `rel` is the repo-relative path.
# --------------------------------------------------------------------------

def detect_version_files(path: Path, rel: str, text: str) -> list[Detection]:
    mapping = {
        ".nvmrc": "nodejs", ".node-version": "nodejs", ".python-version": "python",
        ".ruby-version": "ruby", ".php-version": "php", ".go-version": "go",
        ".java-version": DEFAULT_JAVA_DISTRIBUTION,
        ".terraform-version": "terraform",
        ".bun-version": "bun", ".crystal-version": "crystal",
    }
    product = mapping.get(path.name)
    if not product:
        return []
    version, locked = parse_constraint(text.strip().splitlines()[0] if text.strip() else "")
    if not version:
        return []
    return [Detection(product, version, f"{rel}:1", locked if locked is not None else exact(version))]


def detect_tool_versions(rel: str, text: str) -> list[Detection]:
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        raw = parts[1]
        if parts[0].lower() == "java":
            # `java temurin-21.0.1` names both the distribution and the version.
            distribution, _, remainder = parts[1].partition("-")
            product = JAVA_DISTRIBUTIONS.get(distribution.lower(), DEFAULT_JAVA_DISTRIBUTION)
            raw = remainder or parts[1]
        else:
            product = TOOL_PRODUCTS.get(parts[0].lower())
        if not product:
            continue
        version, locked = parse_constraint(raw)
        if version:
            found.append(Detection(product, version, f"{rel}:{number}", locked if locked is not None else exact(version)))
    return found


def detect_mise_toml(rel: str, text: str) -> list[Detection]:
    found, in_tools = [], False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("["):
            in_tools = stripped in {"[tools]", "[tools.default]"}
            continue
        if not in_tools or "=" not in stripped or stripped.startswith("#"):
            continue
        key, _, value = stripped.partition("=")
        product = TOOL_PRODUCTS.get(key.strip().strip('"').lower())
        if not product:
            continue
        version, locked = parse_constraint(value.split("#")[0].strip().strip('[]'))
        if version:
            found.append(Detection(product, version, f"{rel}:{number}", locked if locked is not None else exact(version)))
    return found


def detect_dockerfile(rel: str, text: str) -> list[Detection]:
    args: dict[str, str] = {}
    stages: set[str] = set()
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        arg = re.match(r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)", stripped, re.IGNORECASE)
        if arg:
            args[arg.group(1)] = arg.group(2).strip("\"'")
            continue
        from_line = re.match(
            r"^FROM\s+(?:--\S+\s+)*(?P<image>\S+)(?:\s+[Aa][Ss]\s+(?P<stage>\S+))?",
            stripped,
        )
        if not from_line:
            continue
        image = from_line.group("image")
        if from_line.group("stage"):
            stages.add(from_line.group("stage").lower())
        # Substitute ARG defaults so `FROM node:${NODE_VERSION}` resolves.
        for name, value in args.items():
            image = image.replace(f"${{{name}}}", value).replace(f"${name}", value)
        if image.lower() in stages or image.lower() == "scratch":
            continue
        parts = split_image(image)
        if not parts:
            continue
        product = docker_product(parts[0])
        version = docker_tag_version(parts[1])
        if product and version:
            found.append(Detection(product, version, f"{rel}:{number}", exact(version)))
    return found


def detect_image_references(rel: str, text: str) -> list[Detection]:
    """`image: postgres:15` in compose files and workflow service blocks."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = re.match(r"^\s*(?:-\s*)?image:\s*[\"']?([^\"'\s#]+)", line)
        if not match:
            continue
        parts = split_image(match.group(1))
        if not parts:
            continue
        product = docker_product(parts[0])
        version = docker_tag_version(parts[1])
        if product and version:
            found.append(Detection(product, version, f"{rel}:{number}", exact(version)))
    return found


ENGINES_KEY = '"engines"'


def detect_package_json(rel: str, data: dict, text: str) -> list[Detection]:
    found = []
    engines = data.get("engines")
    if isinstance(engines, dict):
        version, locked = parse_constraint(engines.get("node"))
        if version:
            found.append(Detection("nodejs", version,
                                   f"{rel}:{line_of(text, ENGINES_KEY)}",
                                   locked if locked is not None else exact(version)))
    dependencies = {}
    for section in ("dependencies", "devDependencies"):
        value = data.get(section)
        if isinstance(value, dict):
            dependencies.update(value)
    for name, product in NPM_PRODUCTS.items():
        if name not in dependencies:
            continue
        version, locked = parse_constraint(dependencies[name])
        if version:
            found.append(Detection(product, version,
                                   f"{rel}:{line_of(text, chr(34) + name + chr(34))}",
                                   locked if locked is not None else exact(version)))
    return found


def detect_composer_json(rel: str, data: dict, text: str) -> list[Detection]:
    found = []
    require = data.get("require")
    if not isinstance(require, dict):
        return found
    for name, product in COMPOSER_PRODUCTS.items():
        if name not in require:
            continue
        version, locked = parse_constraint(require[name])
        if version:
            found.append(Detection(product, version,
                                   f"{rel}:{line_of(text, chr(34) + name + chr(34))}",
                                   locked if locked is not None else exact(version)))
    return found


def detect_python_requirements(rel: str, text: str) -> list[Detection]:
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|~=|>)\s*([0-9][^\s,;]*)", stripped)
        if not match:
            continue
        product = PYPI_PRODUCTS.get(match.group(1).lower().replace("_", "-"))
        if not product:
            continue
        version, locked = parse_constraint(f"{match.group(2)}{match.group(3)}")
        if version:
            found.append(Detection(product, version, f"{rel}:{number}", locked if locked is not None else exact(version)))
    return found


def detect_pyproject(rel: str, text: str) -> list[Detection]:
    found = []
    match = re.search(r'^\s*requires-python\s*=\s*["\']([^"\']+)', text, re.MULTILINE)
    if match:
        version, locked = parse_constraint(match.group(1))
        if version:
            found.append(Detection("python", version,
                                   f"{rel}:{line_of(text, 'requires-python')}",
                                   locked if locked is not None else exact(version)))
    match = re.search(r'^\s*python\s*=\s*["\']([^"\']+)', text, re.MULTILINE)
    if match and not found:
        version, locked = parse_constraint(match.group(1))
        if version:
            found.append(Detection("python", version, f"{rel}:{line_of(text, 'python =')}",
                                   locked if locked is not None else exact(version)))
    return found


def detect_go_mod(rel: str, text: str) -> list[Detection]:
    match = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", text, re.MULTILINE)
    if not match:
        return []
    return [Detection("go", match.group(1), f"{rel}:{line_of(text, match.group(0))}",
                      exact(match.group(1)))]


def detect_gemfile(rel: str, text: str) -> list[Detection]:
    found = []
    match = re.search(r'^\s*ruby\s+["\']([^"\']+)', text, re.MULTILINE)
    if match:
        version, locked = parse_constraint(match.group(1))
        if version:
            found.append(Detection("ruby", version, f"{rel}:{line_of(text, match.group(0))}",
                                   locked if locked is not None else exact(version)))
    for name, product in GEM_PRODUCTS.items():
        match = re.search(rf'^\s*gem\s+["\']{re.escape(name)}["\']\s*,\s*["\']([^"\']+)',
                          text, re.MULTILINE)
        if match:
            version, locked = parse_constraint(match.group(1))
            if version:
                found.append(Detection(product, version, f"{rel}:{line_of(text, match.group(0))}",
                                       locked if locked is not None else exact(version)))
    return found


def detect_dotnet(rel: str, text: str) -> list[Detection]:
    found = []
    for match in re.finditer(r"<TargetFrameworks?>([^<]+)</TargetFrameworks?>", text):
        for framework in match.group(1).split(";"):
            moniker = re.match(r"^net(\d+\.\d+)", framework.strip())
            if moniker:
                found.append(Detection("dotnet", moniker.group(1),
                                       f"{rel}:{line_of(text, match.group(0))}",
                                       exact(moniker.group(1))))
    return found


def detect_global_json(rel: str, data: dict, text: str) -> list[Detection]:
    sdk = data.get("sdk")
    if not isinstance(sdk, dict) or not sdk.get("version"):
        return []
    version, _ = parse_constraint(sdk["version"])
    if not version:
        return []
    cycle = ".".join(version.split(".")[:2])
    return [Detection("dotnet", cycle, f"{rel}:{line_of(text, 'version')}", exact(cycle))]


def detect_terraform(rel: str, text: str) -> list[Detection]:
    match = re.search(r'required_version\s*=\s*["\']([^"\']+)', text)
    if not match:
        return []
    version, locked = parse_constraint(match.group(1))
    if not version:
        return []
    return [Detection("terraform", version, f"{rel}:{line_of(text, match.group(0))}",
                      locked if locked is not None else exact(version))]


def detect_cloud_runtimes(rel: str, text: str) -> list[Detection]:
    """`runtime: nodejs18.x` (Lambda / SAM / App Engine / Cloud Functions)."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = re.match(r'^\s*[Rr]untime:\s*[\"\']?([A-Za-z0-9._]+)', line)
        if not match:
            continue
        runtime = CLOUD_RUNTIME.match(match.group(1))
        if not runtime or not runtime.group("ver"):
            continue
        product = CLOUD_RUNTIME_PRODUCTS.get(runtime.group("name").lower())
        if not product:
            continue
        raw = runtime.group("ver").replace("_", ".")
        # App Engine writes `python312`; Lambda writes `python3.12`.
        if "." not in raw and len(raw) > 2 and product in {"python", "dotnet"}:
            raw = f"{raw[0]}.{raw[1:]}"
        found.append(Detection(product, raw, f"{rel}:{number}", exact(raw)))
    return found


def detect_setup_actions(rel: str, text: str) -> list[Detection]:
    """`actions/setup-node` and friends define the CI runtime; drift hides here."""
    mapping = {
        "node-version": "nodejs", "python-version": "python", "ruby-version": "ruby",
        "php-version": "php", "go-version": "go",
        "java-version": DEFAULT_JAVA_DISTRIBUTION,
        "terraform_version": "terraform", "deno-version": "deno", "bun-version": "bun",
    }
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = re.match(r"^\s*([a-z_\-]+):\s*[\"']?([^\"'\s#]+)", line)
        if not match:
            continue
        product = mapping.get(match.group(1))
        if not product:
            continue
        version, locked = parse_constraint(match.group(2))
        if version:
            found.append(Detection(product, version, f"{rel}:{number}", locked if locked is not None else exact(version)))
    return found


def detect_wordpress(rel: str, text: str) -> list[Detection]:
    match = re.search(r"\$wp_version\s*=\s*['\"]([0-9][^'\"]*)", text)
    if not match:
        return []
    return [Detection("wordpress", match.group(1), f"{rel}:{line_of(text, match.group(0))}",
                      exact(match.group(1)))]


def scan_repository(root: Path) -> list[Detection]:
    detections: list[Detection] = []
    for path in iter_files(root):
        name = path.name
        lowered = name.lower()
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            continue
        suffix = path.suffix.lower()

        if name in {".nvmrc", ".node-version", ".python-version", ".ruby-version",
                    ".php-version", ".go-version", ".java-version",
                    ".terraform-version", ".bun-version", ".crystal-version"}:
            detections += detect_version_files(path, rel, read_text(path))
        elif name == ".tool-versions":
            detections += detect_tool_versions(rel, read_text(path))
        elif lowered in {"mise.toml", ".mise.toml", "mise.local.toml", ".config/mise.toml"}:
            detections += detect_mise_toml(rel, read_text(path))
        elif lowered.startswith("dockerfile") or lowered.endswith(".dockerfile"):
            detections += detect_dockerfile(rel, read_text(path))
        elif name == "package.json":
            text = read_text(path)
            detections += detect_package_json(rel, load_json(path), text)
        elif name == "composer.json":
            text = read_text(path)
            detections += detect_composer_json(rel, load_json(path), text)
        elif name == "global.json":
            text = read_text(path)
            detections += detect_global_json(rel, load_json(path), text)
        elif name == "go.mod":
            detections += detect_go_mod(rel, read_text(path))
        elif name in {"Gemfile", "gems.rb"}:
            detections += detect_gemfile(rel, read_text(path))
        elif name == "pyproject.toml":
            detections += detect_pyproject(rel, read_text(path))
        elif lowered.startswith("requirements") and suffix in {".txt", ".in"}:
            detections += detect_python_requirements(rel, read_text(path))
        elif suffix in {".csproj", ".fsproj", ".vbproj"}:
            detections += detect_dotnet(rel, read_text(path))
        elif suffix == ".tf":
            detections += detect_terraform(rel, read_text(path))
        elif name == "version.php" and "wp-includes" in rel.replace(os.sep, "/"):
            detections += detect_wordpress(rel, read_text(path))
        elif suffix in {".yml", ".yaml"}:
            text = read_text(path)
            normalised = rel.replace(os.sep, "/")
            if lowered.startswith("docker-compose") or lowered == "compose.yml" \
                    or lowered == "compose.yaml" or "image:" in text:
                detections += detect_image_references(rel, text)
            if normalised.startswith(".github/workflows/") or normalised.startswith(".gitlab"):
                detections += detect_setup_actions(rel, text)
            if lowered.startswith("serverless") or lowered in {"template.yaml", "template.yml"} \
                    or lowered == "app.yaml" or "runtime:" in text:
                detections += detect_cloud_runtimes(rel, text)
    return detections


# --------------------------------------------------------------------------
# endoflife.date client
# --------------------------------------------------------------------------

class EndOfLifeClient:
    def __init__(self, retries: int = 3, timeout: int = 20) -> None:
        self.retries = retries
        self.timeout = timeout
        self._products: dict[str, dict] = {}
        self._index: set[str] | None = None

    def _get(self, url: str) -> dict | None:
        last_error: Exception | None = None
        for attempt in range(self.retries):
            request = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT, "Accept": "application/json",
            })
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    return None
                last_error = error
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
                last_error = error
        raise RuntimeError(f"endoflife.date request failed for {url}: {last_error}")

    def index(self) -> set[str]:
        if self._index is None:
            payload = self._get(f"{API_ROOT}/products/") or {}
            names: set[str] = set()
            for entry in payload.get("result", []):
                names.add(entry["name"])
                names.update(entry.get("aliases") or [])
            self._index = names
        return self._index

    def product(self, name: str) -> dict | None:
        if name not in self._products:
            payload = self._get(f"{API_ROOT}/products/{name}")
            self._products[name] = (payload or {}).get("result") or {}
        return self._products[name] or None


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

def version_tuple(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", name))


def match_release(releases: list[dict], version: str) -> dict | None:
    """Pick the release cycle a version belongs to.

    Only matches when the version is at least as specific as the cycle name,
    so a bare `php 8` is never attributed to the 8.0 cycle it may not run.
    """
    parts = version.split(".")
    best: dict | None = None
    best_depth = -1
    for release in releases:
        cycle_parts = str(release.get("name", "")).split(".")
        if len(cycle_parts) > len(parts) or parts[:len(cycle_parts)] != cycle_parts:
            continue
        if len(cycle_parts) > best_depth:
            best, best_depth = release, len(cycle_parts)
    return best


def candidate_releases(releases: list[dict], version: str, locked: int) -> list[dict]:
    """Every cycle a declaration could actually resolve to.

    `"php": "^8.1"` locks the major, so its candidates are 8.1 through 8.5 —
    not 8.0, which the `>= 8.1` floor excludes.
    """
    if locked <= 0:
        return []
    parts = version.split(".")
    wanted = parts[:locked]
    candidates = []
    for release in releases:
        cycle = str(release.get("name", ""))
        if not cycle or not cycle[0].isdigit():
            continue
        cycle_parts = cycle.split(".")
        shared = min(len(cycle_parts), locked)
        if cycle_parts[:shared] != wanted[:shared]:
            continue
        overlap = min(len(cycle_parts), len(parts))
        if version_tuple(".".join(cycle_parts[:overlap])) < version_tuple(".".join(parts[:overlap])):
            continue  # below the declared floor
        candidates.append(release)
    return candidates


def as_date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def is_eol(release: dict, today: date) -> bool:
    eol = as_date(release.get("eolFrom"))
    return bool(release.get("isEol")) or bool(eol and eol <= today)


def classify(release: dict, today: date, warn_days: int) -> tuple[str, int | None]:
    eol = as_date(release.get("eolFrom"))
    eoas = as_date(release.get("eoasFrom"))
    days = (eol - today).days if eol else None
    if is_eol(release, today):
        return "eol", days
    if release.get("isEoas") or (eoas and eoas <= today):
        return "eoas", days
    if days is not None and days <= warn_days:
        return "approaching-eol", days
    if eoas and (eoas - today).days <= warn_days:
        return "approaching-eoas", days
    return "supported", days


def newest_supported(releases: list[dict]) -> str | None:
    for release in releases:
        if release.get("isMaintained") and not release.get("isEol"):
            return str(release.get("name"))
    return None


STATUS_RANK = {
    "eol": 0, "eoas": 1, "approaching-eol": 2, "approaching-eoas": 3,
    "supported": 4, "unknown": 5,
}


def evaluate(detections: list[Detection], client: EndOfLifeClient, today: date,
             warn_days: int, ignores: list[dict]) -> list[dict]:
    """Resolve detections to release cycles and grade each one.

    Findings are keyed by (product, cycle) rather than by raw version, so a
    `.tool-versions` pin of 1.5.7 and a `~> 1.5` constraint collapse into the
    single Terraform 1.5 cycle they both describe.
    """
    index = client.index()
    grouped: dict[tuple[str, str], dict] = {}

    for detection in detections:
        if detection.product not in index:
            continue
        product = client.product(detection.product)
        if not product:
            continue
        releases = product.get("releases") or []
        release = match_release(releases, detection.version)
        cycle = str(release.get("name")) if release else None

        # A declaration blocks only when every cycle it could resolve to is
        # already dead; otherwise it is advisory, however old the floor looks.
        candidates = candidate_releases(releases, detection.version, detection.locked)
        enforced = bool(candidates) and all(is_eol(r, today) for r in candidates)

        key = (detection.product, cycle or f"?{detection.version}")
        entry = grouped.setdefault(key, {
            "product": detection.product,
            "cycle": cycle,
            "release": release,
            "releases": releases,
            "label": product.get("label") or detection.product,
            "link": (product.get("links") or {}).get("html")
                    or f"https://endoflife.date/{detection.product}",
            "versions": set(),
            "sources": set(),
            "enforced": False,
        })
        entry["versions"].add(detection.version)
        entry["sources"].add(detection.source)
        entry["enforced"] = entry["enforced"] or enforced

    findings: list[dict] = []
    for (product_name, _), entry in grouped.items():
        release = entry["release"]
        if release is None:
            status, days = "unknown", None
            eol_date = eoas_date = latest = None
        else:
            status, days = classify(release, today, warn_days)
            eol_date = release.get("eolFrom")
            eoas_date = release.get("eoasFrom")
            latest = (release.get("latest") or {}).get("name")

        finding = {
            "product": product_name,
            "label": entry["label"],
            "cycle": entry["cycle"],
            "versions": sorted(entry["versions"], key=version_tuple),
            "status": status,
            "enforced": entry["enforced"],
            "eol_date": eol_date,
            "eoas_date": eoas_date,
            "days_until_eol": days,
            "latest_in_cycle": latest,
            "newest_supported_cycle": newest_supported(entry["releases"]),
            "sources": sorted(entry["sources"]),
            "link": entry["link"],
            "ignored": False,
            "ignore_reason": None,
        }
        for rule in ignores:
            if rule.get("product") != product_name:
                continue
            wanted = rule.get("version")
            if wanted not in (None, "*", entry["cycle"]) and wanted not in finding["versions"]:
                continue
            finding["ignored"] = True
            finding["ignore_reason"] = rule.get("reason") or "no reason recorded"
            break
        findings.append(finding)

    findings.sort(key=lambda f: (STATUS_RANK.get(f["status"], 9), f["product"],
                                 version_tuple(f["cycle"] or "")))
    return findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

LABELS = {
    "eol": "EOL", "eoas": "WARN", "approaching-eol": "WARN",
    "approaching-eoas": "WARN", "supported": "OK", "unknown": "INFO",
}


def component_name(finding: dict) -> str:
    return f"{finding['product']} {finding['cycle'] or finding['versions'][0]}"


def describe(finding: dict) -> str:
    status, days = finding["status"], finding["days_until_eol"]
    if status == "eol":
        when = f"EOL {finding['eol_date']}"
        return f"{when} ({abs(days)} days ago)" if days is not None else when
    if status == "eoas":
        return (f"active support ended {finding['eoas_date']}, "
                f"EOL {finding['eol_date'] or 'not scheduled'}")
    if status == "approaching-eol":
        return f"EOL {finding['eol_date']} (in {days} days)"
    if status == "approaching-eoas":
        return f"active support ends {finding['eoas_date']}"
    if status == "unknown":
        return "no matching release cycle on endoflife.date"
    return f"EOL {finding['eol_date'] or 'not scheduled'}"


def render_table(findings: list[dict]) -> str:
    if not findings:
        return "No tracked runtime or framework components were detected."
    lines = []
    for finding in findings:
        if finding["ignored"]:
            label = "SKIP"
        elif finding["status"] == "eol":
            label = "FAIL" if finding["enforced"] else "WARN"
        else:
            label = LABELS.get(finding["status"], "INFO")
        lines.append(f"{label:<5} {component_name(finding):<30} {describe(finding)}")
        detail = f"declared {', '.join(finding['versions'])} in {', '.join(finding['sources'][:4])}"
        lines.append(f"{'':<5} {'':<30} {detail}")
        if finding["ignored"]:
            lines.append(f"{'':<5} {'':<30} exception: {finding['ignore_reason']}")
    return "\n".join(lines)


def render_summary(findings: list[dict], repository: str, blocking: list[dict],
                   warning: list[dict]) -> str:
    out = ["### End-of-life component scan", "",
           f"Repository `{repository}` — {len(findings)} tracked component(s) detected.", ""]
    if not findings:
        out.append("No tracked runtime or framework components were detected.")
        return "\n".join(out)
    if blocking:
        out.append(f"**{len(blocking)} component(s) past end of life are blocking this run.**")
    elif warning:
        out.append(f"{len(warning)} component(s) need attention but are not blocking.")
    else:
        out.append("Every detected component is still in support.")
    out += ["", "| Status | Component | Detail | Move to | Declared in |",
            "| --- | --- | --- | --- | --- |"]
    listed = 0
    for finding in findings:
        if finding["status"] == "supported" and not finding["ignored"]:
            continue
        listed += 1
        if finding["ignored"]:
            label = "exception"
        elif finding["status"] == "eol":
            label = "**end of life**" if finding["enforced"] else "end of life (advisory)"
        else:
            label = finding["status"].replace("-", " ")
        sources = ", ".join(f"`{source}`" for source in finding["sources"][:3])
        out.append(
            f"| {label} | [{finding['label']}]({finding['link']}) "
            f"{finding['cycle'] or finding['versions'][0]} | {describe(finding)} "
            f"| {finding['newest_supported_cycle'] or '—'} | {sources} |"
        )
    if not listed:
        out = out[:4] + ["Every detected component is still in support."]
    else:
        out += ["", "Components still in support are omitted here; the job log lists them all.",
                "", "An advisory end-of-life row comes from an open version range "
                "(`>=18`, `^8.1`) that could still resolve to a supported release, so it "
                "reports but does not block."]
    return "\n".join(out)


# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", default=".", help="repository root to scan")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "unknown"))
    parser.add_argument("--warn-days", type=int, default=90)
    parser.add_argument("--ignore-file", default="")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--summary-out", default="")
    parser.add_argument("--fail-on-eol", default="true")
    args = parser.parse_args()

    ignores: list[dict] = []
    if args.ignore_file and Path(args.ignore_file).is_file():
        payload = json.loads(Path(args.ignore_file).read_text(encoding="utf-8") or "{}")
        ignores = payload.get("ignore") or []

    today = datetime.now(timezone.utc).date()
    detections = scan_repository(Path(args.path).resolve())
    client = EndOfLifeClient()
    findings = evaluate(detections, client, today, args.warn_days, ignores)

    blocking, warning = [], []
    for finding in findings:
        if finding["ignored"] or finding["status"] not in {
            "eol", "eoas", "approaching-eol", "approaching-eoas"
        }:
            continue
        (blocking if finding["status"] == "eol" and finding["enforced"] else warning).append(finding)

    print(render_table(findings))
    print()

    for finding in blocking:
        print(f"::error::{component_name(finding)} is past end of life "
              f"({describe(finding)}). Move to "
              f"{finding['newest_supported_cycle'] or 'a supported release'}. "
              f"Declared in {finding['sources'][0]}.")
    for finding in warning:
        print(f"::warning::{component_name(finding)}: {describe(finding)}. "
              f"Declared in {finding['sources'][0]}.")

    report = {
        "repository": args.repository,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "warn_days": args.warn_days,
        "blocking": len(blocking),
        "components": findings,
    }
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.summary_out:
        with open(args.summary_out, "a", encoding="utf-8") as handle:
            handle.write(render_summary(findings, args.repository, blocking, warning) + "\n")

    if blocking and args.fail_on_eol.lower() == "true":
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"::error::{error}")
        sys.exit(2)
