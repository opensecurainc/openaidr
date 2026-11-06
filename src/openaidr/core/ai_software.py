"""Known AI software, matched conservatively against installed-software records.

A record is AI software only when its identifier starts with a listed vendor
prefix or its name equals a listed product name (case-insensitive). Nothing is
inferred from descriptions, publishers, or partial names, so an unlisted AI
product is reported as an ordinary application rather than guessed at.
"""

# Bundle or package identifier prefixes owned by AI vendors or products.
IDENTIFIER_PREFIXES = (
    "com.anthropic.",  # Claude, Claude Code
    "com.openai.",  # ChatGPT, Codex
    "com.electron.ollama",  # Ollama for macOS
    "com.todesktop.230313mzl4w4u92",  # Cursor
    "com.exafunction.windsurf",  # Windsurf
    "ai.elementlabs.lmstudio",  # LM Studio
    "ai.perplexity.",  # Perplexity
    "com.workbuddy.workbuddy-ai",  # WorkBuddy AI for macOS
)

# Exact product names, compared case-insensitively. Covers package managers and
# Windows registrations whose identifiers do not carry a vendor prefix.
NAMES = (
    "chatgpt",
    "claude",
    "claude code",
    "codex",
    "openai.codex",
    "cursor",
    "github copilot",
    "gpt4all",
    "lm studio",
    "ollama",
    "perplexity",
    "windsurf",
    "workbuddy",
    "workbuddy ai",
)

# Supporting components can be hidden without hiding the application itself.
# Match exact identifiers or names; a name containing "helper" is not evidence.
HELPER_IDENTIFIERS = ("com.anthropic.claude-code-url-handler",)
HELPER_NAMES = ("claude code url handler",)

# General-purpose products remain outside AI review even when they bundle
# optional AI features. Match installation identifiers, never publisher prefixes.
GENERAL_PURPOSE_IDENTIFIERS = frozenset({
    "com.google.chrome", "google chrome",
    "com.microsoft.edgemac", "microsoft edge",
    "com.apple.safari", "com.microsoft.outlook",
    "microsoft.outlookforwindows_8wekyb3d8bbwe",
    "microsoft.paint_8wekyb3d8bbwe", "microsoft.mspaint_8wekyb3d8bbwe",
})

APP_NAMES = {name: name.replace(" ", "-") for name in NAMES}
APP_NAMES["workbuddy ai"] = "workbuddy"
APP_IDENTIFIERS = {
    "com.openai.chat": "chatgpt",
    "com.openai.codex": "codex",
    "com.anthropic.claudefordesktop": "claude",
    "com.anthropic.claude": "claude",
    "com.anthropic.claude-code": "claude-code",
    "com.anthropic.code": "claude-code",
    "com.electron.ollama": "ollama",
    "com.todesktop.230313mzl4w4u92": "cursor",
    "com.exafunction.windsurf": "windsurf",
    "ai.elementlabs.lmstudio": "lm-studio",
    "com.workbuddy.workbuddy-ai": "workbuddy",
}
PACKAGE_PRODUCTS = {
    "npm": {
        "@anthropic-ai/claude-code": "claude-code",
        "@openai/codex": "codex",
        "@google/gemini-cli": "gemini-cli",
        "@github/copilot": "copilot-cli",
    },
    "pypi": {"aider-chat": "aider", "hermes-agent": "hermes-agent"},
}


def application_product(identifier, name, source):
    identifier, name = identifier.lower(), name.lower()
    if source == "openaidr-cli":
        ecosystem, _, package = identifier.partition(":")
        return PACKAGE_PRODUCTS.get(ecosystem, {}).get(package)
    # Appx reports the package family, while its Name retains OpenAI.Codex.
    # Do not match similarly named helpers or a different package family.
    if (source == "windows-appx" and name == "openai.codex"
            and identifier.split("_", 1)[0] == "openai.codex"):
        return "codex"
    return APP_IDENTIFIERS.get(identifier) or APP_NAMES.get(name)


def known_application(identifier, name, source):
    identifier, name = identifier.lower(), name.lower()
    if identifier in HELPER_IDENTIFIERS or name in HELPER_NAMES:
        return False
    if source == "openaidr-cli":
        if identifier.startswith("executable:"):
            return False
        if application_product(identifier, name, source):
            return True
    return identifier.startswith(IDENTIFIER_PREFIXES) or name in NAMES


