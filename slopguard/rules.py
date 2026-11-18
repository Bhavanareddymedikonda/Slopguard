"""slopguard: ignore-file  (this file *defines* the patterns, so it matches them)

Regex rule catalogue (language agnostic).

A rule says *what* to look for, *where* (code / comment / raw line) and in
which kinds of files. Everything else - ranking, test-file downgrading,
suppression - is handled by the scanner.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from .models import Severity

S = Severity


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


PLACEHOLDER_RE = re.compile(
    r"(your[_\-\s]?|my[_\-\s]?|example|changeme|change[_\-]me|placeholder|dummy|sample|"
    r"xxxx|\*\*\*|<[^>]+>|\$\{|\{\{|%\(|todo|fixme|insert|replace|redacted|fake|test)",
    re.I,
)


def _is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RE.search(value)) or len(set(value)) <= 3


def _hardcoded_secret_ok(m: "re.Match[str]") -> bool:
    """Reject env lookups, placeholders and low-entropy values."""
    value = m.group("val")
    if len(value) < 6 or _is_placeholder(value):
        return False
    if re.fullmatch(r"[a-z]+(?:[-_.][a-z]+)*", value):
        return False  # plain lowercase words ('quoted-string'), not a secret
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", value) and shannon_entropy(value) < 3.0:
        return False  # looks like an identifier / enum, not a secret
    return True


def _high_entropy_ok(m: "re.Match[str]") -> bool:
    value = m.group("val")
    if _is_placeholder(value):
        return False
    if re.fullmatch(r"[0-9a-fA-F]{32,}", value):
        return False  # hashes / ids, too noisy
    if re.search(r"https?://|[/\\]\w+\.\w{2,4}$", value):
        return False
    return shannon_entropy(value) >= 4.3


def _password_default_ok(m: "re.Match[str]") -> bool:
    return not _is_placeholder(m.group("val"))


def _real_ip_ok(m: "re.Match[str]") -> bool:
    ip = m.group("ip")
    if ip.startswith(("0.", "127.", "255.", "10.0.0.", "192.168.")) or ip in {"1.1.1.1", "8.8.8.8"}:
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


@dataclass(frozen=True)
class Rule:
    id: str
    category: str                 # security | slop | gap
    severity: Severity
    title: str
    pattern: "re.Pattern[str]"
    message: str
    fix: str = ""
    scope: str = "code"           # code | comment | line | raw
    kinds: Tuple[str, ...] = ("code", "config")
    confidence: float = 0.8
    ok: Optional[Callable[["re.Match[str]"], bool]] = None
    langs: Optional[Tuple[str, ...]] = None  # restrict to these languages
    not_langs: Tuple[str, ...] = ()
    keep_in_tests: bool = False   # secrets in tests are still worth flagging


def R(id, category, severity, title, pattern, message, fix="", **kw) -> Rule:
    flags = kw.pop("flags", 0)
    return Rule(id, category, severity, title, re.compile(pattern, flags), message, fix, **kw)


_SECRET_NAME = r"(?:pass(?:word|wd)?|secret|token|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?key|private[_\-]?key|client[_\-]?secret|credentials?)"

RULES = [
    # ------------------------------------------------------------------ security
    R("SEC001", "security", S.CRITICAL, "Private key committed",
      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
      "A private key is stored in the repository.",
      "Remove it, rotate the key and load it from a secret manager.",
      scope="raw", kinds=("code", "config", "doc"), confidence=0.98, keep_in_tests=True),
    R("SEC002", "security", S.CRITICAL, "AWS access key id",
      r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
      "Looks like an AWS access key id.",
      "Revoke the key and use IAM roles or environment variables.",
      scope="raw", kinds=("code", "config", "doc"), confidence=0.9, keep_in_tests=True,
      ok=lambda m: not _is_placeholder(m.group(0)) and "EXAMPLE" not in m.group(0)),
    R("SEC003", "security", S.CRITICAL, "API token with a well-known prefix",
      r"\b(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|"
      r"xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{35}|"
      r"sk-ant-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{32,}|glpat-[A-Za-z0-9_\-]{20})\b",
      "A provider API token is hardcoded.",
      "Revoke the token and read it from the environment.",
      scope="raw", kinds=("code", "config", "doc"), confidence=0.95, keep_in_tests=True),
    R("SEC004", "security", S.HIGH, "Hardcoded credential",
      r"""(?ix)\b[\w.\-]*""" + _SECRET_NAME + r"""(?:[_\-]?(?:value|str|string|text|b64|hex))?["']?\s*(?::|=|=>|:=)\s*["'](?P<val>[^"'\s]{6,})["']""",
      "A password, key or token appears to be hardcoded.",
      "Move it to an environment variable or secret manager and rotate it.",
      scope="code", kinds=("code", "config"), confidence=0.75, ok=_hardcoded_secret_ok,
      keep_in_tests=False),
    R("SEC005", "security", S.MEDIUM, "High-entropy string assigned to a secret-like name",
      r"""(?ix)\b[\w.\-]*""" + _SECRET_NAME + r"""(?:[_\-]?(?:value|str|string|text|b64|hex))?["']?\s*(?::|=|=>|:=)\s*["'](?P<val>[A-Za-z0-9+/_=\-]{20,})["']""",
      "A long random-looking value is assigned to a secret-like name.",
      "Load secrets from the environment instead of source.",
      scope="code", kinds=("code", "config"), confidence=0.6, ok=_high_entropy_ok),
    R("SEC006", "security", S.HIGH, "Credentials embedded in a URL",
      r"""[a-z][a-z0-9+.\-]{2,}://[^\s:/@"'<>]{2,}:(?P<val>[^\s@/"'<>]{3,})@[\w.\-]+""",
      "A connection string contains a username and password.",
      "Use environment variables for credentials and never commit them.",
      scope="raw", kinds=("code", "config", "doc"), confidence=0.8, ok=_password_default_ok),
    R("SEC007", "security", S.HIGH, "Dynamic code execution (eval/exec)",
      r"(?<![\w.])(?:eval|exec)\s*\((?!\s*[\"'][^\"']*[\"']\s*\))",
      "Evaluating dynamic strings can run attacker-controlled code.",
      "Use a safe parser (ast.literal_eval, JSON) or an explicit dispatch table.",
      langs=("python", "javascript", "typescript", "php", "ruby", "perl", "lua", "r"),
      confidence=0.65),
    R("SEC008", "security", S.HIGH, "Shell command built from dynamic input",
      r"\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call)|"
      r"child_process\.(?:exec|execSync)|\bexec(?:Sync)?|Runtime\.getRuntime\(\)\.exec|"
      r"shell_exec|passthru|proc_open|system)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*[+%]|[\"'][^\"']*[\"']\s*\.\s*format|`[^`]*\$\{|[^\"'\s)]+\s*\+)",
      "A shell command is assembled by concatenating or formatting strings.",
      "Pass arguments as a list (no shell) and validate or escape every input.",
      confidence=0.7),
    R("SEC009", "security", S.MEDIUM, "subprocess with shell=True",
      r"shell\s*=\s*True",
      "shell=True makes command injection possible if any input is untrusted.",
      "Pass a list of arguments and drop shell=True.",
      langs=("python",), confidence=0.7),
    R("SEC010", "security", S.HIGH, "SQL built with string formatting",
      r"""(?ix)(?:\b(?:select\s[^"']*?\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^"'\n]*["']?\s*(?:\+|%\s*[\w(]|\.format\()|
          \bf["'](?:[^"'\n]*\b(?:select|insert|update|delete)\b[^"'\n]*\{)|
          ["'`][^"'`\n]*\b(?:select|insert|update|delete)\b[^"'`\n]*\$\{)""",
      "SQL appears to be built by string concatenation or interpolation.",
      "Use parameterised queries or an ORM.",
      confidence=0.65),
    R("SEC011", "security", S.HIGH, "Unsafe deserialisation",
      r"\b(?:pickle\.loads?|cPickle\.loads?|marshal\.loads?|yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe))|"
      r"unserialize\s*\(|ObjectInputStream|Marshal\.load|BinaryFormatter|jsonpickle\.decode)",
      "Deserialising untrusted data can lead to remote code execution.",
      "Use JSON or yaml.safe_load, and never deserialise untrusted input.",
      confidence=0.7),
    R("SEC012", "security", S.MEDIUM, "Weak hash for security purposes",
      r"""(?i)\b(?:md5|sha-?1)\b\s*(?:\(|\.new|\.create|\.digest|\.hexdigest)|createHash\(\s*["'](?:md5|sha1)["']|MessageDigest\.getInstance\(\s*["'](?:MD5|SHA-?1)["']""",
      "MD5/SHA-1 are broken for passwords and signatures.",
      "Use SHA-256+ (or bcrypt/argon2 for passwords).",
      confidence=0.55),
    R("SEC013", "security", S.HIGH, "TLS certificate verification disabled",
      r"(?i)verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
      r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|"
      r"ssl\._create_unverified_context|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER",
      "Disabling TLS verification exposes traffic to man-in-the-middle attacks.",
      "Keep verification on; pin or install the proper CA instead.",
      confidence=0.85),
    R("SEC014", "security", S.MEDIUM, "Non-cryptographic randomness for secrets",
      r"""(?ix)\b(?:token|secret|password|passwd|session|nonce|salt|otp|csrf|api[_\-]?key)\w*\s*(?:=|:)\s*[^\n]*
          (?:\brandom\.(?:random|randint|choice|choices|randrange)\s*\(|Math\.random\s*\(|\brand\s*\(|\bmt_rand\s*\()""",
      "Predictable random numbers are being used for a security value.",
      "Use secrets / crypto.randomBytes / SecureRandom.",
      confidence=0.65),
    R("SEC015", "security", S.MEDIUM, "Wildcard CORS",
      r"""(?i)(?:access-control-allow-origin["']?\s*[:,=]\s*["']?\*|allow_origins\s*=\s*\[\s*["']\*["']\s*\]|origin\s*:\s*["']\*["']|cors\(\s*\))""",
      "Any website can call this API from a user's browser.",
      "Restrict CORS to the exact origins you trust.",
      confidence=0.6),
    R("SEC016", "security", S.MEDIUM, "Debug mode enabled",
      r"""(?ix)(?:\bdebug\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*(?:True|1)\b|\bDEBUG\s*:\s*true\b|display_errors\s*=\s*(?:on|1|true))""",
      "Debug mode can leak stack traces and enable remote consoles in production.",
      "Drive debug flags from the environment and default to off.",
      confidence=0.6),
    R("SEC017", "security", S.MEDIUM, "Server bound to all interfaces",
      r"""(?:["']0\.0\.0\.0["']|host\s*=\s*0\.0\.0\.0|--host[= ]0\.0\.0\.0)""",
      "Listening on 0.0.0.0 exposes the service on every network interface.",
      "Bind to 127.0.0.1 unless public access is intended, and put it behind a proxy.",
      kinds=("code",), confidence=0.4),
    R("SEC018", "security", S.MEDIUM, "Cross-site scripting sink",
      r"""\.innerHTML\s*[+]?=|dangerouslySetInnerHTML|document\.write\s*\(|v-html\s*=|\|\s*safe\b|mark_safe\s*\(|\.html\(\s*[^)"']""",
      "Writing untrusted data into the DOM unescaped enables XSS.",
      "Use textContent / escaping, or sanitise with a vetted library.",
      confidence=0.55),
    R("SEC019", "security", S.MEDIUM, "Insecure temp file or world-writable permissions",
      r"""\bmktemp\s*\(|chmod\s*\(?[^)\n]*0?777|chmod\s+(?:-R\s+)?777|os\.chmod\([^)]*0o?777""",
      "Predictable temp files or 777 permissions invite local attacks.",
      "Use secure temp APIs and least-privilege permissions.",
      confidence=0.7),
    R("SEC020", "security", S.MEDIUM, "Possible path traversal / unsafe file path",
      r"""(?ix)\b(?:open|readFile(?:Sync)?|sendFile|send_file|file_get_contents|fopen)\s*\([^)\n]*(?:request|req\.|params|query|\$_(?:GET|POST|REQUEST)|argv)""",
      "A file path appears to come directly from user input.",
      "Normalise the path and enforce an allow-listed base directory.",
      confidence=0.55),
    R("SEC021", "security", S.HIGH, "Disabled security feature or auth bypass",
      r"""(?ix)(?:csrf\w*\s*[:=]\s*(?:false|off)|@csrf_exempt|\bverify_signature\s*[:=]\s*false|algorithms?\s*[:=]\s*\[?\s*["']none["']|
          \bauth(?:entication|orization)?\s*[:=]\s*(?:false|none)\b|\bskip_?auth\w*\s*[:=]\s*true|--no-verify|StrictHostKeyChecking\s*=?\s*no)""",
      "A security control is turned off.",
      "Re-enable it, or document and constrain the exception.",
      confidence=0.6),
    R("SEC022", "security", S.MEDIUM, "Docker: runs as root or unpinned image",
      r"(?im)^\s*(?:USER\s+root\b|FROM\s+[\w./\-]+(?::latest)?\s*$)",
      "Container runs as root or uses an unpinned/latest base image.",
      "Pin the image version/digest and add a non-root USER.",
      langs=("dockerfile",), kinds=("code",), confidence=0.6),
    R("SEC023", "security", S.MEDIUM, "Remote script piped into a shell",
      r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b",
      "Executing a downloaded script without verifying it is risky.",
      "Download, verify a checksum/signature, then run.",
      kinds=("code", "config", "doc"), scope="raw", confidence=0.6),
    R("SEC024", "security", S.LOW, "Hardcoded public IP address",
      r"""["'](?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?["']""",
      "A fixed IP address is embedded in code.",
      "Move endpoints to configuration.",
      kinds=("code",), confidence=0.35, ok=_real_ip_ok),
    R("SEC025", "security", S.MEDIUM, "Default or empty password",
      r"""(?ix)\bpass(?:word|wd)?\w*\s*[:=]\s*["'](?P<val>admin|root|password|pass|123456|12345678|default|guest|toor|qwerty|letmein)?["']""",
      "A default or blank password is configured.",
      "Require a strong, unique secret from the environment.",
      confidence=0.55, ok=lambda m: m.group("val") is not None or "[" not in m.string),

    # ---------------------------------------------------------------------- slop
    R("SLP001", "slop", S.MEDIUM, "Swallowed exception",
      r"""(?ix)(?:except(?:\s+\w[\w.]*)?(?:\s+as\s+\w+)?\s*:\s*(?:pass|\.\.\.|continue)\s*$|
          catch\s*(?:\([^)]*\))?\s*\{\s*\}|rescue(?:\s+\w+)?\s*(?:=>\s*\w+)?\s*;?\s*$(?=\s*\n\s*end)|
          if\s+err\s*!=\s*nil\s*\{\s*\})""",
      "An error is caught and silently ignored.",
      "Log it, handle it or re-raise it - never swallow it silently.",
      scope="code", confidence=0.75),
    R("SLP002", "slop", S.LOW, "Bare/overbroad exception handler",
      r"""(?x)^\s*except\s*:|^\s*except\s+(?:Base)?Exception\b\s*(?:as\s+\w+)?\s*:|\bcatch\s*\(\s*(?:final\s+)?(?:Throwable|Exception|e|err|error|ex)\s*(?::\s*any)?\s*\)\s*\{\s*(?://.*)?$""",
      "Catching everything hides real bugs.",
      "Catch the specific exceptions you can actually handle.",
      confidence=0.4),
    R("SLP003", "slop", S.LOW, "Debug output left in code",
      r"""(?x)(?<![\w.])(?:print\s*\(|pprint\s*\(|breakpoint\s*\(\s*\)|pdb\.set_trace\s*\(|ipdb\.set_trace\s*\(|
          console\.(?:log|debug|dir|trace)\s*\(|\bdebugger\s*;|var_dump\s*\(|print_r\s*\(|
          System\.out\.println\s*\(|fmt\.Print(?:ln|f)?\s*\(\s*["']DEBUG|dbg!\s*\(|binding\.pry)""",
      "Debug statements usually should not ship.",
      "Replace with proper logging or delete.",
      kinds=("code",), confidence=0.45,
      not_langs=("shell", "make", "dockerfile", "sql", "css", "scss", "html", "terraform")),
    R("SLP004", "slop", S.LOW, "Commented-out debug or code line",
      r"""^\s*(?://|#|--)\s*(?:console\.log|print\s*\(|import\s+\w|from\s+\w+\s+import|return\b|var_dump|System\.out)""",
      "Dead commented-out code adds noise.",
      "Delete it - version control remembers.",
      scope="line", kinds=("code",), confidence=0.55),
    R("SLP005", "slop", S.MEDIUM, "AI-assistant leftover / boilerplate phrase",
      r"""(?ix)\b(?:as\s+an\s+ai(?:\s+language\s+model)?|i(?:'m|\s+am)\s+(?:sorry|unable|not\s+able)\b|
          i\s+(?:cannot|can't)\s+(?:assist|help)\s+with|here(?:'s|\s+is)\s+(?:the|an?|your)\s+(?:updated|complete|full|revised|improved|corrected)\s+(?:code|version|implementation|file)|
          (?:rest|remainder|remaining|other)\s+(?:of\s+)?(?:the\s+)?(?:code|implementation|logic|methods?|functions?|file)\s+(?:remains?|stays?|goes|here)|
          \.\.\.\s*(?:existing|rest\s+of|other)\s+(?:code|implementation|logic)\b|
          (?:your|add|insert|put)\s+(?:actual\s+)?(?:code|logic|implementation)\s+here|implementation\s+goes\s+here|
          in\s+a\s+real(?:-world)?\s+(?:app|application|world|scenario|implementation|project)|
          for\s+(?:demonstration|demo|illustration|simplicity)\s+purposes?|
          this\s+is\s+(?:just\s+)?a\s+(?:simple|basic|dummy|mock|placeholder|simplified)\s+(?:example|implementation|function|version)|
          you\s+(?:would|should|could|can|will)\s+(?:typically|normally|usually)?\s*(?:replace|implement|add|use)\b[^.\n]{0,40}\b(?:here|this|real))""",
      "Text typical of an AI assistant or unfinished scaffolding was left in the code.",
      "Replace it with the real implementation or remove it.",
      scope="line", kinds=("code", "config"), confidence=0.7),
    R("SLP006", "slop", S.LOW, "Pointless narrating comment",
      r"""(?ix)^\s*(?://|\#|--|/\*+|\*)\s*(?:
          (?:this|the)\s+(?:function|method|class|code|loop|block|variable|line)\s+(?:is\s+used\s+to|will|is\s+responsible\s+for|does|handles?|defines?|creates?|returns?|initiali[sz]es?)\b|
          (?:import|importing)\s+(?:the\s+)?(?:required|necessary|needed)\s+(?:libraries|modules|packages|dependencies)|
          (?:define|create|initiali[sz]e|declare|set\s+up|set)\s+(?:a\s+|an\s+|the\s+)?(?:new\s+)?(?:variable|function|class|list|array|dictionary|object|constant)s?\b|
          (?:loop|iterate)\s+(?:through|over)\s+(?:the\s+)?\w+|
          (?:return|returns)\s+(?:the\s+)?(?:result|value|output|data)\s*\.?\s*$|
          increment(?:s|ing)?\s+(?:the\s+)?(?:counter|i|index)|main\s+(?:function|entry)\s*(?:point)?\s*$|constructor\s*$|getters?\s*(?:and|&)\s*setters?\s*$
          )""",
      "A comment that only restates the code is classic AI/boilerplate padding.",
      "Delete it, or explain *why* instead of *what*.",
      scope="line", kinds=("code",), confidence=0.45),
    R("SLP007", "slop", S.LOW, "Overly generic identifier",
      r"""(?x)\b(?:def|function|func|fn|fun|void|public|private|static|class)\s+(?:(?:static|async|final)\s+)*
          (?P<n>(?:do_?something|do_?stuff|handle_?data|process_?data|helper|helper_?function|my_?function|my_?func|temp_?func|foo|bar|baz|blah|test_?func|func1|func2|function1|function2|new_?function|untitled|stuff|thing|data_?handler|util_?function)\b)""",
      "Placeholder-style names indicate unfinished or low-effort code.",
      "Give it a name that says what it does.",
      kinds=("code",), confidence=0.55, flags=re.I),
    R("SLP008", "slop", S.LOW, "Magic hardcoded values / sleep hack",
      r"""(?x)\b(?:time\.sleep|Thread\.sleep|sleep|setTimeout|usleep)\s*\(\s*(?:\d{3,}|[1-9]\d?\s*\*\s*\d{2,})""",
      "Long hardcoded sleeps are usually a workaround for a race or retry problem.",
      "Use proper synchronisation, backoff or a named constant.",
      kinds=("code",), confidence=0.35),
    R("SLP009", "slop", S.LOW, "Returns a hardcoded stub value",
      r"""(?ix)^\s*return\s+(?:["'](?:ok|success|done|true|test|todo|n/?a|none|dummy|mock|stub|hello world)["']|\{\s*["']?(?:status|message|result)["']?\s*:\s*["'](?:ok|success|done)["']\s*\})\s*;?\s*$""",
      "A function returns a canned value that may be a stub.",
      "Implement the real behaviour or mark the function clearly as a stub.",
      kinds=("code",), confidence=0.4),
    R("SLP010", "slop", S.INFO, "Type-safety escape hatch",
      r"""(?x)(?::\s*any\b|<any>|\bas\s+any\b|@ts-ignore|@ts-nocheck|\#\s*type:\s*ignore|\bunsafe\s*\{|//\s*eslint-disable(?:-next-line|-line)?\b|\#\s*noqa\b|\#\s*pylint:\s*disable|@SuppressWarnings)""",
      "A lint/type check is being bypassed.",
      "Fix the underlying type or lint problem, or justify it in a comment.",
      scope="raw", kinds=("code",), confidence=0.3),
    R("SLP011", "slop", S.LOW, "Placeholder text in code",
      r"""(?ix)\b(?:lorem\s+ipsum|foo\s*bar\s*baz|asdf+g*|qwerty|test\s*123|example\.com/(?:api|endpoint)|your[_\-\s]api[_\-\s]key[_\-\s]here|john\s+doe|jane\s+doe|(?:sample|dummy|fake|mock)\s+(?:data|text|user|name|response))\b""",
      "Placeholder content suggests unfinished work.",
      "Replace it with real content or load it from fixtures.",
      scope="raw", kinds=("code",), confidence=0.35),

    # ----------------------------------------------------------------- gaps
    R("GAP001", "gap", S.LOW, "TODO / FIXME / HACK marker",
      r"""(?x)(?<![A-Za-z])(?P<tag>TODO|FIXME|XXX|HACK|BUG|KLUDGE|REFACTOR|OPTIMI[SZ]E|WORKAROUND|TEMP(?:ORARY)?)(?![A-Za-z_]{2,})\b\s*(?:\([^)]*\))?\s*(?::|-|\s)""",
      "An unfinished or flagged piece of work is noted in a comment.",
      "Resolve it or link it to a tracked issue.",
      scope="comment", kinds=("code", "config"), confidence=0.85),
    R("GAP002", "gap", S.LOW, "Unimplemented stub",
      r"""(?ix)(?:raise\s+NotImplementedError\b|throw\s+new\s+(?:Error|\w*Exception)\s*\(\s*["'`](?:not\s+(?:yet\s+)?implemented|unimplemented|todo)[^"'`]*["'`]|
          \bunimplemented!\s*\(|\btodo!\s*\(|\bpanic\s*\(\s*["'](?:not\s+implemented|unimplemented|todo)|
          \bthrow\s+new\s+NotImplementedException|NotImplementedError\s*\()""",
      "Code path is declared but not implemented.",
      "Implement it or remove the dead path.",
      kinds=("code",), confidence=0.7),
    R("GAP003", "gap", S.LOW, "Empty function / placeholder body",
      r"""(?x)(?:^\s*(?:def|function|fn|func)\s+\w+\s*\([^)]*\)\s*(?:->\s*[\w\[\], .|]+)?\s*:\s*(?:pass|\.\.\.)\s*$|
          \bfunction\s*\w*\s*\([^)]*\)\s*\{\s*\}|\b\w+\s*\([^)]*\)\s*(?::\s*\w+\s*)?\{\s*(?://\s*(?:todo|implement)[^\n]*)?\}\s*$)""",
      "Function body is empty.",
      "Implement it, or if it is an abstract hook, document that.",
      kinds=("code",), confidence=0.45, not_langs=("css", "scss", "html", "terraform", "sql")),
    R("GAP004", "gap", S.MEDIUM, "Disabled or skipped test",
      r"""(?x)(?:@pytest\.mark\.(?:skip|xfail)\b|@unittest\.skip\w*|\b(?:it|test|describe)\.(?:skip|todo)\s*\(|\bx(?:it|describe|test)\s*\(|@Ignore\b|@Disabled\b|t\.Skip\s*\(|\#\[ignore\]|\bpytest\.skip\s*\()""",
      "A test is switched off.",
      "Fix or delete the test; do not leave it dormant.",
      kinds=("code",), confidence=0.65),
    R("GAP005", "gap", S.LOW, "Assertion-free or always-true test",
      r"""(?ix)(?:\bassert\s+True\b|assertTrue\(\s*True\s*\)|expect\(\s*true\s*\)\.toBe\(\s*true\s*\)|assert\.ok\(\s*true\s*\)|assertEquals\(\s*1\s*,\s*1\s*\))""",
      "A test that cannot fail verifies nothing.",
      "Assert the real behaviour.",
      kinds=("code",), confidence=0.8),
    R("GAP006", "gap", S.LOW, "Network call without timeout",
      r"""(?x)\b(?:requests|httpx|urllib\.request|http\.client)\.(?:get|post|put|patch|delete|head|request|urlopen)\s*\((?![^)]*timeout)[^)]*\)""",
      "HTTP calls without a timeout can hang forever.",
      "Pass an explicit timeout.",
      langs=("python",), kinds=("code",), confidence=0.55),
    R("GAP007", "gap", S.LOW, "Unpinned dependency",
      r"""(?x)^\s*(?P<pkg>[A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*$""",
      "Dependency has no version constraint, making builds non-reproducible.",
      "Pin or bound the version.",
      scope="line", kinds=("config",), langs=("requirements",), confidence=0.6),
    R("GAP008", "gap", S.LOW, "Floating dependency version (*/latest)",
      r"""["'](?P<pkg>[@\w./\-]+)["']\s*:\s*["'](?:\*|latest|x)["']""",
      "Wildcard dependency versions are a supply-chain risk.",
      "Pin an exact or caret-bounded version.",
      langs=("json",), kinds=("config",), confidence=0.7),
    R("GAP009", "gap", S.LOW, "Hardcoded localhost URL",
      r"""["'`]https?://(?:localhost|127\.0\.0\.1)(?::\d+)?[^"'`]*["'`]""",
      "Development URL is hardcoded.",
      "Read the base URL from configuration.",
      kinds=("code",), confidence=0.35),
    R("GAP010", "gap", S.LOW, "Missing await / unhandled promise",
      r"""(?x)^\s*\w+(?:\.\w+)*\.(?:then)\s*\((?![^)]*catch)[^)]*\)\s*;?\s*$""",
      "A promise chain has no catch handler.",
      "Add .catch(...) or use try/await.",
      langs=("javascript", "typescript"), kinds=("code",), confidence=0.35),
    R("GAP011", "gap", S.LOW, "Ignored error return",
      r"""(?x)^\s*_\s*(?:,\s*_)?\s*(?:=|:=)\s*\w+(?:\.\w+)*\(""",
      "An error value is thrown away.",
      "Handle the returned error.",
      langs=("go",), kinds=("code",), confidence=0.45),
]

BY_ID = {r.id: r for r in RULES}
