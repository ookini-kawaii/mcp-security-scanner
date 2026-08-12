VERSION = "1.3.0"

"""Context-aware static scanner for MCP tool metadata and source files."""

from .engine import MCPSecurityScanner
from .integrity import IntegrityManifestError, build_manifest, compare_manifest, load_manifest, save_manifest
from .models import ScanResult

__all__ = [
    "MCPSecurityScanner", "ScanResult", "VERSION",
    "IntegrityManifestError", "build_manifest", "compare_manifest",
    "load_manifest", "save_manifest",
]
