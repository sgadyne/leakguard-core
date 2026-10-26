"""Inert public host adapter imports; construction and actions are explicit."""
from .errors import HostError
from .navigation import browse, capabilities, reveal, roots
from .scheduler import HostService, HostStateStore
from .services import service_spec
from .ssh import SSHRunner

__version__ = "0.2.0"
__all__ = ["HostError", "HostService", "HostStateStore", "SSHRunner", "browse", "capabilities", "reveal", "roots", "service_spec"]
