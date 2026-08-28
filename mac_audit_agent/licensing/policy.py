from __future__ import annotations

from dataclasses import dataclass

from .models import CORE_SAFETY_FEATURES

PRODUCT_ID = "com.liquidskysecurity.msaa"
PRODUCT_NAME = "MSAA"
PROVISIONAL_LICENSOR = "Liquidsky Network Security"
LICENSE_SCHEMA_VERSION = 1
OFFLINE_LICENSE_CONTACT = "pwn@mail.lv"
OFFLINE_LICENSE_PRICE_USD = 10
OFFLINE_LICENSE_TERM = "month"
DEFAULT_LICENSE_CHECKOUT_URL = "https://licenses.liquidskysecurity.com/v1/checkout"
DEFAULT_LICENSE_ACTIVATION_URL = "https://licenses.liquidskysecurity.com/v1/activate"


@dataclass(frozen=True)
class LicensingPolicy:
    product_id: str = PRODUCT_ID
    maximum_document_bytes: int = 262_144
    activation_timeout_seconds: float = 20.0
    maximum_activation_response_bytes: int = 524_288
    clock_rollback_tolerance_seconds: int = 300
    expiring_warning_days: int = 30
    allow_private_activation_hosts: bool = False
    operator_unlock_activation_modes: frozenset[str] = frozenset({"offline", "stripe"})
    core_safety_features: frozenset[str] = CORE_SAFETY_FEATURES


DEFAULT_POLICY = LicensingPolicy()
