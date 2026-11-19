"""Detection rules. Each rule is a regex applied line by line."""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHT = {"low": 3, "medium": 10, "high": 25, "critical": 40}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    pattern: re.Pattern
    advice: str


def _r(rule_id, title, severity, category, regex, advice, flags=re.IGNORECASE):
    return Rule(rule_id, title, severity, category, re.compile(regex, flags), advice)


RULES = [
    _r(
        "SA001", "Remote script piped into an interpreter", "critical", "execution",
        r"\b(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(bash|sh|zsh|python3?|node|perl|ruby)\b",
        "Download the script, review it, pin a checksum, then run it.",
    ),
    _r(
        "SA002", "Destructive command", "critical", "destruction",
        r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(--no-preserve-root\s+)?(/\*?|~/?|\$HOME/?|\*)(\s|$)"
        r"|\bmkfs(\.\w+)?\b|\bdd\s+if=\S+\s+of=/dev/",
        "A skill should never wipe home, root or disks. Scope deletes to a specific path.",
    ),
    _r(
        "SA003", "Access to credentials or key material", "high", "secrets",
        r"\.ssh/|\.aws/credentials|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.kube/config"
        r"|\.gnupg|\bid_(rsa|ed25519)\b|/etc/shadow|find-generic-password|Login Data",
        "Skills rarely need credentials. Remove it or document exactly why it is required.",
    ),
    _r(
        "SA004", "Possible data exfiltration", "high", "exfiltration",
        r"\b(curl|wget)\b[^\n]*(-d\s*@|--data(-binary|-raw|-urlencode)?\s+@|-F\s+\S*@|--upload-file)"
        r"|\b(nc|ncat|netcat)\s+\S+\s+\d+|\|\s*(curl|nc|ncat)\b",
        "Sending local files or piped data to a remote host is a classic exfiltration pattern.",
    ),
    _r(
        "SA005", "Prompt-injection or concealment instruction", "high", "injection",
        r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|rules|prompts)"
        r"|disregard (all |any )?(the )?(previous|prior|above|system)"
        r"|do not (tell|inform|mention|reveal)[^\n]{0,40}(user|human)"
        r"|without (telling|informing|notifying) the (user|human)"
        r"|\b(secretly|covertly)\b"
        r"|you are now in (developer|dan|god) mode|override (the )?(system|safety)",
        "Legitimate skills do not tell the agent to hide actions from the user or discard rules.",
    ),
    _r(
        "SA006", "Hidden Unicode characters", "high", "injection",
        "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]",
        "Zero-width and bidi characters can smuggle instructions invisible to reviewers.",
        flags=0,
    ),
    _r(
        "SA007", "Hardcoded secret", "critical", "secrets",
        r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        r"|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_\-]{35}",
        "Remove the secret, rotate it, and load credentials from the environment instead.",
        flags=0,
    ),
    _r(
        "SA009", "Privilege escalation or disabled safety checks", "medium", "privilege",
        r"\bsudo\b|chmod\s+(-R\s+)?(777|a\+rwx)|--dangerously-skip-permissions|--no-sandbox"
        r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|verify\s*=\s*False|curl\s+[^\n]*\s(-k|--insecure)\b",
        "Avoid root, world-writable files and disabled TLS or sandbox checks.",
    ),
    _r(
        "SA010", "Obfuscated or encoded execution", "high", "execution",
        r"base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh|\beval\s*\(\s*(atob|base64|b64decode)"
        r"|exec\s*\(\s*(base64\.)?b64decode|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){7,}",
        "Encoded payloads that are decoded and executed hide what the skill really does.",
    ),
    _r(
        "SA011", "Persistence mechanism", "medium", "persistence",
        r"\bcrontab\b|/etc/cron|\.bashrc|\.zshrc|\.profile\b|LaunchAgents|LaunchDaemons"
        r"|systemctl\s+enable|/etc/rc\.local",
        "Skills should not install themselves into shell startup files or schedulers.",
    ),
    _r(
        "SA012", "Known data-sink or tunnel domain", "high", "exfiltration",
        r"https?://[^\s\"')]*(pastebin\.com|transfer\.sh|webhook\.site|requestbin|ngrok\.io"
        r"|ngrok-free\.app|discord(app)?\.com/api/webhooks|hastebin|0x0\.st)",
        "These services are commonly used to receive stolen data.",
    ),
    _r(
        "SA013", "Network call to a raw IP address", "medium", "exfiltration",
        r"https?://(?!127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.)\d{1,3}(\.\d{1,3}){3}\b",
        "Prefer named, well-known hosts. Raw IPs hide the destination.",
    ),
    _r(
        "SA014", "Instruction hidden in an HTML comment", "medium", "injection",
        r"<!--.*\b(instruction|ignore|assistant|system|execute|curl|send|exfiltrate)\b.*-->",
        "HTML comments are invisible when rendered but still read by the agent.",
    ),
]

# Rules that are not regex based (see scanner.py), listed for `skillaudit rules`.
SPECIAL_RULES = [
    ("SA008", "Over-broad allowed-tools (unscoped Bash or wildcard)", "medium", "privilege"),
    ("SA015", "SKILL.md is missing frontmatter or a description", "low", "quality"),
    ("SA016", "Opaque binary file that cannot be audited", "medium", "execution"),
    ("SA017", "Symlink pointing outside the skill directory", "high", "execution"),
]
