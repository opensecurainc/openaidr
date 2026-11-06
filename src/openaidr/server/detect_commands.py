"""Non-executing shell tokenizer and transfer classifier."""

from dataclasses import dataclass, field
import re
from urllib.parse import urlsplit
from .detect_constants import curlValueOpts, wgetValueOpts


@dataclass
class Segment:
    op: str
    argv: list[str]
    raw: str
    name: str = ""
    args: list[str] = field(default_factory=list)

    def __post_init__(self):
        a = self.argv[:]
        while a:
            head = re.split(r"[/\\]", a[0])[-1].lower().removesuffix(".exe")
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", a[0]):
                a = a[1:]
                continue
            options = None
            if head in ("sudo", "doas"):
                options = {"-u", "-g", "-C", "-D", "-p", "-r", "-t", "-U", "-T", "-h"}
            elif head == "env":
                if len(a) == 1:
                    self.name = head
                    return
                options = {"-u"}
            elif head in ("nohup", "time", "command", "exec", "builtin", "caffeinate"):
                options = set()
            elif head in ("nice", "ionice"):
                options = {"-n", "-c"}
            elif head == "timeout":
                options = {"-s", "-k"}
            if options is None:
                self.name, self.args = head, a[1:]
                return
            a = a[1:]
            while a and (
                a[0].startswith("-")
                or head == "env"
                and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", a[0])
            ):
                a = a[2:] if a[0] in options and len(a) > 1 else a[1:]
            if head == "timeout":
                a = a[1:]


def split(cmd, depth=0):
    segs, argv, token, raw = [], [], "", ""
    active, op, quote, paren, backtick = False, "", "", 0, False
    i = 0

    def flush():
        nonlocal token, active
        if active:
            argv.append(token)
            token, active = "", False

    def end(next_op):
        nonlocal argv, raw, op
        flush()
        if argv:
            segs.append(Segment(op, argv, raw.strip()))
        argv, raw, op = [], "", next_op

    while i < len(cmd):
        c = cmd[i]
        raw += c
        nxt = cmd[i + 1 : i + 2]
        i += 1
        if quote:
            if c == "\\" and quote == '"' and nxt:
                token += nxt
                raw += nxt
                i += 1
            elif c == quote:
                quote = ""
            else:
                token += c
            continue
        if backtick:
            token += c
            if c == "`":
                backtick = False
            continue
        if paren:
            token += c
            paren += (c == "(") - (c == ")")
            continue
        if c == "\\":
            if nxt and nxt in " \t\n\"'$`\\|&;()<>*?[]#~!{}":
                i += 1
                raw += nxt
                if nxt != "\n":
                    token += nxt
                    active = True
            else:
                token += c
                active = True
        elif c in "'\"":
            quote, active = c, True
        elif c == "`":
            backtick, active = True, True
            token += c
        elif c == "$":
            active = True
            token += c
            if nxt == "(":
                token += nxt
                raw += nxt
                i += 1
                paren = 1
        elif c in " \t":
            flush()
        elif c in "\n;":
            end(c)
        elif c in "|&":
            if c == "&" and active and token.endswith(">"):
                token += c
            elif c == "&" and nxt == ">":
                flush()
                token, active = c, True
            elif nxt == c or c == "|" and nxt == "&":
                i += 1
                raw += nxt
                end(c + nxt if nxt == c else "|")
            else:
                end(c)
        elif c in "()" and not active:
            pass
        else:
            token += c
            active = True
    end("")
    if depth < 3:
        result = []
        for s in segs:
            result.append(s)
            if s.name in ("sh", "bash", "zsh", "dash", "ksh", "fish"):
                for j, a in enumerate(s.args[:-1]):
                    if a.startswith("-") and not a.startswith("--") and "c" in a:
                        inner = split(s.args[j + 1], depth + 1)
                        for sub in inner:
                            sub.op = sub.op or s.op
                        result.extend(inner)
                        break
        return result
    return segs


@dataclass
class Egress:
    tool: str
    host: str
    url: str = ""
    upload: bool = False
    sends_data: bool = False
    files: list[str] = field(default_factory=list)
    pipe_to_shell: bool = False
    seg: Segment | None = None


def host_of(raw):
    if not raw.strip():
        return ""
    try:
        return (
            urlsplit(raw if "://" in raw else "http://" + raw).hostname or ""
        ).lower()
    except ValueError:
        return raw.split("://")[-1].split("/")[0].split("@")[-1].split(":")[0].lower()


def non_flag_args(args, value_opts=()):
    out, i = [], 0
    while i < len(args):
        a = args[i]
        i += 1
        if a.startswith("-"):
            if a in value_opts:
                i += 1
        else:
            out.append(a)
    return out


def remote_host(op):
    if op.startswith(("scp://", "sftp://", "rsync://")):
        return host_of(op)
    if re.match(r"^[A-Za-z]:", op):
        return ""
    m = re.match(r"^(?:[^@/:\s]+@)?([A-Za-z0-9._-]+|\[[0-9a-fA-F:]+\]):", op)
    return m[1].strip("[]") if m else ""


def _web_egress(s):
    urls, files, upload, sends = [], [], False, False
    opts = curlValueOpts if s.name == "curl" else wgetValueOpts
    i = 0
    while i < len(s.args):
        a = s.args[i]
        i += 1
        if a == "--":
            urls.extend(s.args[i:])
            break
        name, val, has_val = a, "", False
        if a.startswith("--") and "=" in a:
            name, val = a.split("=", 1)
            has_val = True
        elif a.startswith("-") and not a.startswith("--") and len(a) > 2:
            for j, c in enumerate(a[1:], 1):
                name = "-" + c
                if name in opts:
                    if j + 1 < len(a):
                        val, has_val = a[j + 1 :], True
                    break
        if a.startswith("-"):
            if name not in opts:
                continue
            if not has_val and i < len(s.args):
                val = s.args[i]
                i += 1
            if name in (
                "-d",
                "--data",
                "--data-binary",
                "--data-ascii",
                "--data-raw",
                "--data-urlencode",
                "--json",
            ):
                sends = True
                if val.startswith("@") and name != "--data-raw":
                    upload = True
                    files.append(val[1:])
                elif name == "--data-urlencode" and "@" in val:
                    upload = True
                    files.append(val.split("@", 1)[1])
            elif name in ("-F", "--form"):
                sends = True
                match = re.search(r"=[@<](.*)", val)
                if match:
                    upload = True
                    files.append(match[1])
            elif name in ("-T", "--upload-file", "--post-file", "--body-file"):
                upload = sends = True
                files.append(val)
            elif name in ("--post-data", "--body-data"):
                sends = True
            elif name == "--url":
                urls.append(val)
            elif name in ("-X", "--request") and val.upper() in (
                "POST",
                "PUT",
                "PATCH",
            ):
                sends = True
        elif (
            "://" in a
            or a.startswith("localhost")
            or re.match(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:/|$)", a)
        ):
            urls.append(a)
    return [Egress(s.name, host_of(u), u, upload, sends, files[:]) for u in urls]


def egresses(segs):
    result = []
    for i, s in enumerate(segs):
        eg = []
        if s.name in ("curl", "wget"):
            eg = _web_egress(s)
        elif s.name in ("scp", "sftp", "rsync"):
            opts = (
                {"-P", "-i", "-o", "-F", "-c", "-l", "-S", "-J", "-D"}
                if s.name != "rsync"
                else {
                    "-e",
                    "--rsh",
                    "--files-from",
                    "--exclude",
                    "--include",
                    "--exclude-from",
                    "--include-from",
                    "--log-file",
                    "--bwlimit",
                    "--timeout",
                    "--port",
                    "--password-file",
                    "--temp-dir",
                    "--partial-dir",
                    "--compare-dest",
                    "--copy-dest",
                    "--link-dest",
                    "--chmod",
                    "--chown",
                    "--backup-dir",
                    "--suffix",
                    "--out-format",
                    "--max-size",
                    "--min-size",
                    "--block-size",
                    "--address",
                    "--sockopts",
                    "--iconv",
                    "--outbuf",
                    "--remote-option",
                    "-M",
                    "--filter",
                    "-f",
                    "-B",
                    "-T",
                    "--rsync-path",
                }
            )
            operands, local = non_flag_args(s.args, opts), []
            for j, operand in enumerate(operands):
                host = remote_host(operand)
                if not host:
                    local.append(operand)
                else:
                    upload = j == len(operands) - 1 and bool(local)
                    eg.append(Egress(s.name, host, operand, upload, upload, local[:]))
        elif s.name in (
            "ssh",
            "telnet",
            "ftp",
            "lftp",
            "nc",
            "ncat",
            "netcat",
            "socat",
        ):
            netcat = s.name in ("nc", "ncat", "netcat", "socat")
            opts = (
                set("-p -s -w -q -i -T -e -c -o -x -X -P -O -I -M -m".split())
                if netcat
                else set(
                    "-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w -u".split()
                )
            )
            operands = non_flag_args(s.args, opts)
            if operands and not operands[0].startswith(("<", ">")):
                a = operands[0]
                upload = netcat and (
                    s.op == "|"
                    or any(a.startswith("<") and not a.startswith("<<") for a in s.args)
                )
                eg = [
                    Egress(
                        s.name,
                        host_of(a) if "://" in a else a.split("@")[-1],
                        a,
                        upload,
                        upload,
                    )
                ]
        elif s.name in ("aws", "gsutil", "gcloud"):
            args = s.args[:]
            cloud = s.name != "aws"
            if s.name == "gcloud":
                args = args[1:] if args and args[0] == "storage" else []
            if not cloud and (len(args) < 2 or args[0] not in ("s3", "s3api")):
                continue
            if not cloud and args[:2] == ["s3api", "put-object"] and "--bucket" in args:
                j = args.index("--bucket")
                if j + 1 < len(args):
                    eg.append(
                        Egress(
                            "aws s3api",
                            args[j + 1] + ".s3.amazonaws.com",
                            "s3://" + args[j + 1],
                            True,
                            True,
                        )
                    )
            verb = (args[0] if cloud else args[1]) if args else ""
            opts = set(
                "--region --profile --endpoint-url --exclude --include --storage-class --sse --sse-kms-key-id --acl --content-type --metadata --expected-size --bucket --key --body --output -a -h -j -J -n -p -s -u -x -o".split()
            )
            operands = non_flag_args(args[1:] if cloud else args[2:], opts)
            local = []
            prefix = "gs://" if cloud else "s3://"
            for j, a in enumerate(operands):
                if a.startswith(prefix):
                    host = a[len(prefix) :].split("/")[0] + (
                        ".storage.googleapis.com" if cloud else ".s3.amazonaws.com"
                    )
                    upload = (
                        j == len(operands) - 1
                        and bool(local)
                        and verb in ("cp", "sync", "rsync", "mv")
                    )
                    eg.append(
                        Egress(
                            s.name if cloud else "aws s3",
                            host,
                            a,
                            upload,
                            upload,
                            local[:],
                        )
                    )
                else:
                    local.append(a)
        elif (
            s.name == "az"
            and len(s.args) >= 3
            and s.args[0] == "storage"
            and s.args[2] in ("upload", "upload-batch")
        ):
            account = "unknown"
            if "--account-name" in s.args:
                j = s.args.index("--account-name")
                if j + 1 < len(s.args):
                    account = s.args[j + 1]
            eg = [
                Egress(
                    "az storage",
                    account + ".blob.core.windows.net",
                    upload=True,
                    sends_data=True,
                )
            ]
        for item in eg:
            item.seg = s
        result.extend(eg)
        if (
            s.op == "|"
            and i
            and s.name
            in (
                "sh",
                "bash",
                "zsh",
                "dash",
                "ksh",
                "fish",
                "python",
                "python3",
                "perl",
                "ruby",
                "node",
                "php",
                "pwsh",
                "powershell",
            )
        ):
            for item in result:
                if item.seg is segs[i - 1] and item.tool in ("curl", "wget"):
                    item.pipe_to_shell = True
    return result
