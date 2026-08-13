VERSION = "1.3.1"

"""Context-aware static scanner for MCP tool metadata and source files."""

from .engine import MCPSecurityScanner
from .integrity import (
    IntegrityManifestError,
    build_manifest,
    compare_manifest,
    load_manifest,
    save_manifest,
    sign_manifest,
    verify_manifest_signature,
)
from .models import ScanResult

__all__ = [
    "MCPSecurityScanner", "ScanResult", "VERSION",
    "IntegrityManifestError", "build_manifest", "compare_manifest",
    "load_manifest", "save_manifest", "sign_manifest",
    "verify_manifest_signature",
]
