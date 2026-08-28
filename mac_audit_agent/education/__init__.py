"""School-district readiness models.

This package is deliberately separate from CMMC scoring.  It provides internal
readiness decisions only; it does not make legal or certification findings.
"""

from .applicability import evaluate_applicability
from .models import DistrictProfile

__all__ = ["DistrictProfile", "evaluate_applicability"]
