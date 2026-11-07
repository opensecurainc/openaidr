"""Server settings loaded from OPENAIDR_* environment variables."""

import os
import json
import math
import re
from pathlib import Path
from uuid import UUID
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from importlib.util import find_spec

from openaidr_api_client.contracts.origin import browser_origin

if TYPE_CHECKING:
    from openaidr.platform.deployments import RegistrySettings

PLATFORM_AVAILABLE = find_spec("openaidr.platform") is not None
ALL_SERVICES = ("ingest", "api", "detect") + (("admin",) if PLATFORM_AVAILABLE else ())


@dataclass
class Config:
    database_url: str = ""
    listen: str = ":8080"
    services: dict = field(default_factory=lambda: dict.fromkeys(ALL_SERVICES, True))
    public_url: str = "http://localhost:8080"
    admin_public_url: str = ""
    cookie_secure: bool = False
    log_level: str = "info"
    auto_migrate: bool = True
    cost_processing: bool = True
    osv_assessment: bool = True
    application_classification: bool = True
    application_classification_concurrency: int = 100
    api_cost_report_origin: str = ""
    api_settlement_reporting: bool = False
    api_operations_enabled: bool = False
    api_operations_origin: str = ""
    api_operations_token_file: str = field(default="", repr=False)
    api_operations_ca_file: str = ""
    api_operations_alert_rules: dict = field(default_factory=dict)
    summary_report_origin: str = ""
    summary_report_token: str = field(default="", repr=False)
    summary_report_tokens: dict = field(default_factory=dict, repr=False)
    summary_report_bucket: str = ""
    website_origin: str = ""
    website_service_token_sha256: str = field(default="", repr=False)
    tenant_id: str = ""
    require_tenant: bool = False
    auth_mode: str = "local"
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = field(default="", repr=False)
    admin_auth_mode: str = "local"
    admin_google_client_id: str = ""
    admin_google_client_secret: str = field(default="", repr=False)
    admin_google_hosted_domain: str = ""
    platform_email_enabled: bool = False
    platform_email_from: str = ""
    platform_email_credentials: dict = field(default_factory=dict, repr=False)
    device_auth_mode: str = "bearer"
    device_issuer_dir: str = ""
    deployment_registry: "RegistrySettings | None" = None
    cloud_management_enabled: bool = False
    cicd_console_service_account_id: str = ""
    cicd_github_hosts: list = field(default_factory=list)
    provisioning_controller_workload: dict = field(default_factory=dict)
    provisioning_qualification_fixtures: list = field(default_factory=list)
    provisioning_edge_images: dict = field(default_factory=dict)
    provisioning_job_authority_directory: str = ""
    threat_intel_origin: str = ""
    threat_intel_api_key: str = field(default="", repr=False)
    intelligence_origin: str = ""
    intelligence_api_key: str = field(default="", repr=False)
    intelligence_ca_file: str = ""
    intelligence_keys_key: str = field(default="", repr=False)
    free_installation_id: str = ""
    free_device_id: str = ""
    free_secret: str = field(default="", repr=False)
    free_origin: str = "https://api.opensecura.ai"
    free_status: dict = field(default_factory=dict)
    free_failure: str = ""
    # Retained for the external image readiness probe; tenant requests use api/.
    openai_api_key: str = field(default="", repr=False)
    inline_guardrails: bool = False
    inline_guardrail_concurrency: int = 4
    session_detection_scheduling: bool = True
    session_investigator_binary: str = ""
    db_pool_size: int = 16
    auth_pool_size: int = 4
    db_pool_timeout: float = 5
    ingest_concurrency: int = 16
    host_metrics_path: str = ""
    database_diagnostics: bool = False
    telemetry_retention_disk_path: str = ""
    knowledge_mcp_key: str = field(default="", repr=False)
    knowledge_mcp_private_origins: str = ""
    dashboard_mcp_enabled: bool = False
    slack_webhook_key: str = field(default="", repr=False)
    cowork_key: str = field(default="", repr=False)
    skill_scanner_token: str = field(default="", repr=False)

    def set_services(self, services):
        self.services = {}
        for name in services.lower().split(","):
            name = name.strip()
            if name == "all":
                self.services.update(dict.fromkeys(ALL_SERVICES, True))
            elif name:
                self.services[name] = True

    def enabled(self, name):
        return bool(self.services.get(name))

    def browser_origin(self, admin=False):
        value = (
            self.admin_public_url
            if admin and self.admin_public_url
            else self.public_url
        )
        try:
            return browser_origin(value.rstrip("/"))
        except ValueError:
            name = (
                "ADMIN_PUBLIC_URL" if admin and self.admin_public_url else "PUBLIC_URL"
            )
            raise ValueError(
                f"OPENAIDR_{name} must be an HTTP(S) origin without a path"
            ) from None

    def secure_cookie(self, admin=False):
        return self.cookie_secure or self.browser_origin(admin).startswith("https://")

    def validate(self, allow_unbound=False, *, customer=False):
        from openaidr_api_client.client import Connection

        if customer:
            from .service_enrollment import prepare, pending_config
            enrollment = prepare(self)
            if enrollment is not None:
                pending = pending_config(self, enrollment)
                pending.free_installation_id = ""
                pending.validate(allow_unbound, customer=True)
                return
        else:
            from .free_tier import configure
            configure(self)
        connection = Connection.from_config(self)
        if connection:
            self.tenant_id = connection.tenant_id
        if PLATFORM_AVAILABLE:
            from openaidr.platform.config import validate

            validate(self)
        elif (self.enabled("admin") or self.auth_mode != "local" or self.admin_auth_mode != "local"
              or self.device_auth_mode != "bearer" or any((
                  self.admin_public_url, self.oidc_issuer, self.oidc_client_id, self.oidc_client_secret,
                  self.admin_google_client_id, self.admin_google_client_secret, self.admin_google_hosted_domain,
                  self.platform_email_enabled, self.platform_email_from, self.platform_email_credentials,
                  self.device_issuer_dir, self.deployment_registry, self.cloud_management_enabled,
                  self.cicd_console_service_account_id, self.cicd_github_hosts,
                  self.provisioning_controller_workload, self.provisioning_qualification_fixtures,
                  self.provisioning_edge_images, self.provisioning_job_authority_directory,
                  self.api_cost_report_origin, self.api_settlement_reporting,
                  self.api_operations_enabled, self.api_operations_origin, self.api_operations_token_file,
                  self.api_operations_ca_file, self.api_operations_alert_rules,
                  self.summary_report_tokens,
                  self.summary_report_bucket, self.website_origin, self.website_service_token_sha256))):
            raise ValueError("Cloud services require the private platform package")
        if self.dashboard_mcp_enabled:
            from urllib.parse import urlsplit

            origin = urlsplit(self.browser_origin())
            if (not self.tenant_id or not self.enabled("api")
                    or (origin.scheme != "https" and origin.hostname not in ("localhost", "127.0.0.1", "::1"))):
                raise ValueError("Dashboard MCP requires a tenant-bound API and HTTPS (or loopback for development)")
        if self.skill_scanner_token and (
            not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", self.skill_scanner_token)
            or not self.tenant_id or not self.enabled("api") or not self.enabled("ingest")
        ):
            raise ValueError("Skill scanning requires tenant-bound API and ingestion in one process and a random worker token")
        if self.cowork_key:
            from cryptography.fernet import Fernet

            try:
                Fernet(self.cowork_key.encode())
            except (ValueError, TypeError):
                raise ValueError("OPENAIDR_COWORK_KEY must be a Fernet key") from None
        if self.intelligence_keys_key:
            from cryptography.fernet import Fernet

            try:
                Fernet(self.intelligence_keys_key.encode())
            except (ValueError, TypeError):
                raise ValueError("OPENAIDR_INTELLIGENCE_KEYS_KEY must be a Fernet key") from None
        if self.slack_webhook_key:
            from cryptography.fernet import Fernet

            try:
                Fernet(self.slack_webhook_key.encode())
            except (ValueError, TypeError):
                raise ValueError("OPENAIDR_SLACK_WEBHOOK_KEY must be a Fernet key") from None
        if self.database_diagnostics and not self.tenant_id and not allow_unbound:
            raise ValueError("Database diagnostics require a tenant-bound dedicated database")
        if self.telemetry_retention_disk_path:
            from .host_metrics import valid_disk_path

            if not valid_disk_path(self.telemetry_retention_disk_path) or not self.host_metrics_path or not self.tenant_id:
                raise ValueError("Automatic retention requires a tenant and verified host disk metrics path")
        from .summary_report_contract import TOKEN

        if self.summary_report_origin or self.summary_report_token:
            if (browser_origin(self.summary_report_origin) != self.summary_report_origin
                    or not self.summary_report_origin.startswith("https://")
                    or not TOKEN.fullmatch(self.summary_report_token)
                    or not self.tenant_id or not self.enabled("api")):
                raise ValueError("Summary reporting requires an HTTPS origin, upload token and tenant-bound API")
        self.browser_origin()
        for name in ("db_pool_size", "auth_pool_size", "ingest_concurrency", "inline_guardrail_concurrency"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if (type(self.application_classification_concurrency) is not int
                or not 1 <= self.application_classification_concurrency <= 100):
            raise ValueError("application_classification_concurrency must be an integer from 1 to 100")
        if not math.isfinite(self.db_pool_timeout) or self.db_pool_timeout <= 0:
            raise ValueError("db_pool_timeout must be finite and positive")
        if self.require_tenant and not self.tenant_id and not allow_unbound:
            raise ValueError(
                "OPENAIDR_TENANT_ID is required for this dedicated backend"
            )
        if self.tenant_id:
            try:
                self.tenant_id = str(UUID(self.tenant_id))
            except ValueError:
                raise ValueError("OPENAIDR_TENANT_ID must be a UUID") from None
            if self.enabled("admin"):
                raise ValueError(
                    "tenant-bound backends support ingest, api and detect services only"
                )
        if not self.database_url:
            raise ValueError("OPENAIDR_DATABASE_URL is required")
        for name in self.services:
            if name not in ALL_SERVICES:
                raise ValueError(
                    f"unknown service {name!r} (valid: {', '.join(ALL_SERVICES)}, all)"
                )
        if not self.services:
            raise ValueError("no services enabled")

    @classmethod
    def from_env(cls):
        return from_env()


def from_env():

    def env(name, default=""):
        key = "OPENAIDR_" + name
        value = os.environ.get(key)
        secret_file = os.environ.get(key + "_FILE")
        if value and secret_file:
            raise ValueError(f"set only one of {key} or {key}_FILE")
        if secret_file:
            return Path(secret_file).read_text().strip()
        return value or default

    registry = None
    if PLATFORM_AVAILABLE:
        from openaidr.platform.deployments import RegistrySettings

        registry = RegistrySettings.from_env(env)
    elif env("CLOUD_DEPLOYMENTS_ENABLED", "false").lower() not in ("false", "0"):
        raise ValueError("Cloud services require the private platform package")
    config = Config(
        database_url=env("DATABASE_URL"),
        listen=env("LISTEN", ":8080"),
        public_url=env("PUBLIC_URL", "http://localhost:8080").rstrip("/"),
        admin_public_url=env("ADMIN_PUBLIC_URL").rstrip("/"),
        log_level=env("LOG_LEVEL", "info"),
        auto_migrate=env("AUTO_MIGRATE", "true") != "false",
        cost_processing=env("COST_PROCESSING", "true").lower() not in ("false", "0"),
        osv_assessment=env("OSV_ASSESSMENT", "true").lower() not in ("false", "0"),
        api_cost_report_origin=env("API_COST_REPORT_ORIGIN"),
        api_settlement_reporting=env("API_SETTLEMENT_REPORTING", "false").lower() in ("true", "1"),
        api_operations_enabled=env("API_OPERATIONS_ENABLED", "false").lower() in ("true", "1"),
        api_operations_origin=env("API_OPERATIONS_ORIGIN"),
        api_operations_token_file=env("API_OPERATIONS_TOKEN_FILE"),
        api_operations_ca_file=env("API_OPERATIONS_CA_FILE"),
        api_operations_alert_rules=json.loads(env("API_OPERATIONS_ALERT_RULES", "{}")),
        summary_report_origin=env("SUMMARY_REPORT_ORIGIN"),
        summary_report_token=env("SUMMARY_REPORT_TOKEN"),
        summary_report_tokens=json.loads(env("SUMMARY_REPORT_TOKENS", "{}")),
        summary_report_bucket=env("SUMMARY_REPORT_BUCKET"),
        website_origin=env("WEBSITE_ORIGIN").rstrip("/"),
        website_service_token_sha256=env("WEBSITE_SERVICE_TOKEN_SHA256").lower(),
        tenant_id=env("TENANT_ID"),
        require_tenant=env("REQUIRE_TENANT", "false").lower() in ("true", "1"),
        auth_mode=env("AUTH_MODE", "local"),
        oidc_issuer=env("OIDC_ISSUER"),
        oidc_client_id=env("OIDC_CLIENT_ID"),
        oidc_client_secret=env("OIDC_CLIENT_SECRET"),
        admin_auth_mode=env("ADMIN_AUTH_MODE", "local"),
        admin_google_client_id=env("ADMIN_GOOGLE_CLIENT_ID"),
        admin_google_client_secret=env("ADMIN_GOOGLE_CLIENT_SECRET"),
        admin_google_hosted_domain=env("ADMIN_GOOGLE_HOSTED_DOMAIN"),
        platform_email_enabled=env("PLATFORM_EMAIL_ENABLED", "false").lower() in ("true", "1"),
        platform_email_from=env("PLATFORM_EMAIL_FROM"),
        platform_email_credentials=json.loads(env("PLATFORM_EMAIL_CREDENTIALS", "{}")),
        device_auth_mode=env("DEVICE_AUTH_MODE", "bearer"),
        device_issuer_dir=env("DEVICE_ISSUER_DIR"),
        deployment_registry=registry,
        cloud_management_enabled=env("CLOUD_MANAGEMENT_ENABLED", "false").lower() in ("true", "1"),
        cicd_console_service_account_id=env("CICD_CONSOLE_SERVICE_ACCOUNT_ID", ""),
        cicd_github_hosts=json.loads(env("CICD_GITHUB_HOSTS", "[]")),
        provisioning_controller_workload=json.loads(env("PROVISIONING_CONTROLLER_WORKLOAD", "{}")),
        provisioning_qualification_fixtures=json.loads(env("PROVISIONING_QUALIFICATION_FIXTURES", "[]")),
        provisioning_edge_images=json.loads(env("PROVISIONING_EDGE_IMAGES", "{}")),
        provisioning_job_authority_directory=env("PROVISIONING_JOB_AUTHORITY_DIRECTORY", ""),
        threat_intel_origin=env("THREAT_INTEL_ORIGIN"),
        threat_intel_api_key=env("THREAT_INTEL_API_KEY"),
        intelligence_origin=env("INTELLIGENCE_ORIGIN"),
        intelligence_api_key=env("INTELLIGENCE_API_KEY"),
        intelligence_ca_file=os.environ.get("OPENAIDR_INTELLIGENCE_CA_FILE", ""),
        intelligence_keys_key=env("INTELLIGENCE_KEYS_KEY"),
        free_installation_id=env("FREE_INSTALLATION_ID"),
        free_device_id=env("FREE_DEVICE_ID"),
        free_secret=env("FREE_SECRET"),
        free_origin=env("FREE_ORIGIN", "https://api.opensecura.ai"),
        application_classification=env("APPLICATION_CLASSIFICATION", "true").lower() in ("true", "1"),
        application_classification_concurrency=int(env("APPLICATION_CLASSIFICATION_CONCURRENCY", "100")),
        inline_guardrails=env("INLINE_GUARDRAILS", "false").lower() in ("true", "1"),
        inline_guardrail_concurrency=int(env("INLINE_GUARDRAIL_CONCURRENCY", "4")),
        session_detection_scheduling=env("SESSION_DETECTION_SCHEDULING", "true").lower() in ("true", "1"),
        session_investigator_binary=env("SESSION_INVESTIGATOR_BINARY"),
        db_pool_size=int(env("DB_POOL_SIZE", "16")),
        auth_pool_size=int(env("AUTH_POOL_SIZE", "4")),
        db_pool_timeout=float(env("DB_POOL_TIMEOUT", "5")),
        ingest_concurrency=int(env("INGEST_CONCURRENCY", "16")),
        host_metrics_path=env("HOST_METRICS_PATH"),
        database_diagnostics=env("DATABASE_DIAGNOSTICS", "false").lower() in ("true", "1"),
        telemetry_retention_disk_path=env("TELEMETRY_RETENTION_DISK_PATH"),
        knowledge_mcp_key=env("KNOWLEDGE_MCP_KEY"),
        knowledge_mcp_private_origins=env("KNOWLEDGE_MCP_PRIVATE_ORIGINS"),
        dashboard_mcp_enabled=env("DASHBOARD_MCP_ENABLED", "false").lower() in ("true", "1"),
        slack_webhook_key=env("SLACK_WEBHOOK_KEY"),
        cowork_key=env("COWORK_KEY"),
        skill_scanner_token=env("SKILL_SCANNER_TOKEN"),
    )
    config.set_services(env("SERVICES", "all"))
    config.cookie_secure = env("COOKIE_SECURE") in ("true", "1")
    return config
