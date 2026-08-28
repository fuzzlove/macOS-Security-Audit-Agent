"""MSAA Anti-Ransomware readiness and observation engine.

Importing this package starts no worker, sensor, observer, or GUI.
"""

from .adaptive_detector import AdaptiveRansomwareDetector
from .models import ProtectionMode, SensorMode

__all__ = ["AdaptiveRansomwareDetector", "ProtectionMode", "SensorMode"]
