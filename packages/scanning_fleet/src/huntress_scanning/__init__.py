"""Deterministic discovery: reviewed profiles, parsers, and sweep digests."""

from .backend import ScanningBackend
from .handlers import (
    BUILTIN_HANDLERS,
    CANARY_HOST,
    CANARY_ORIGIN,
    EXPOSED_PATHS,
    REDIRECT_PARAMETERS,
    ScanContext,
)
from .http import BoundedHttpClient, safe_join, safe_query
from .models import (
    FindingSpec,
    HttpResponse,
    ScanAuthorizationError,
    ScanError,
    ScanObservation,
    ScanRequestError,
    ScanTimeout,
)
from .parsers import (
    baseline_spec,
    cors_spec,
    directory_listing_spec,
    dns_spec,
    exposed_file_spec,
    open_redirect_spec,
    reflection_spec,
    security_headers_spec,
    sqli_spec,
)
from .profiles import (
    BUILTIN_PROFILE_IDS,
    BUILTIN_PROFILES,
    builtin_profile,
    builtin_profiles,
)
from .sweep import SweepBuilder, default_profiles, order_profiles

__all__ = [
    "BUILTIN_HANDLERS",
    "BUILTIN_PROFILES",
    "BUILTIN_PROFILE_IDS",
    "CANARY_HOST",
    "CANARY_ORIGIN",
    "EXPOSED_PATHS",
    "REDIRECT_PARAMETERS",
    "BoundedHttpClient",
    "FindingSpec",
    "HttpResponse",
    "ScanAuthorizationError",
    "ScanContext",
    "ScanError",
    "ScanObservation",
    "ScanRequestError",
    "ScanTimeout",
    "ScanningBackend",
    "SweepBuilder",
    "baseline_spec",
    "builtin_profile",
    "builtin_profiles",
    "cors_spec",
    "default_profiles",
    "directory_listing_spec",
    "dns_spec",
    "exposed_file_spec",
    "open_redirect_spec",
    "order_profiles",
    "reflection_spec",
    "safe_join",
    "safe_query",
    "security_headers_spec",
    "sqli_spec",
]

__version__ = "0.1.0"
