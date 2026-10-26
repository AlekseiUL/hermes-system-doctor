from .auth_surface import auth_surface_check
from .config import config_check
from .cron import cron_check
from .discovery import discover_home
from .gateway import gateway_check
from .logs import logs_check
from .mcp import mcp_check
from .memory import memory_check
from .plugins import plugins_check
from .post_update import post_update_drift_check
from .profiles import profile_inventory_check
from .skills import skills_check

# Backward-compatible aliases for the initial scaffold import path.
discover_check = discover_home
profile_config_check = config_check

__all__ = [
    "auth_surface_check",
    "config_check",
    "cron_check",
    "discover_check",
    "discover_home",
    "gateway_check",
    "logs_check",
    "mcp_check",
    "memory_check",
    "plugins_check",
    "post_update_drift_check",
    "profile_config_check",
    "profile_inventory_check",
    "skills_check",
]
