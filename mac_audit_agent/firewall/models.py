from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Literal

@dataclass(frozen=True, order=True)
class PortRange:
    start: int; end: int
    def render(self): return str(self.start) if self.start == self.end else f"{self.start}:{self.end}"

@dataclass(frozen=True)
class AddressSelector:
    kind: Literal["any","address","network","table","localhost"] = "any"
    values: tuple[str,...] = ()

@dataclass(frozen=True)
class FirewallRule:
    rule_id: str; name: str; action: Literal["pass","block"] = "block"; direction: Literal["in","out","both"] = "both"
    interfaces: tuple[str,...] = (); address_family: Literal["inet","inet6","any"] = "any"; protocols: tuple[str,...] = ()
    source: AddressSelector = field(default_factory=AddressSelector); destination: AddressSelector = field(default_factory=AddressSelector)
    source_ports: tuple[PortRange,...] = (); destination_ports: tuple[PortRange,...] = (); quick: bool = True; log: bool = False
    state_mode: Literal["keep","modulate","synproxy","none"] = "keep"; label: str = ""; enabled: bool = True; priority: int = 100

@dataclass(frozen=True)
class FirewallPolicy:
    policy_id: str; name: str; description: str = ""; version: int = 1; enabled: bool = False; priority: int = 100
    rules: tuple[FirewallRule,...] = (); created_by: str = "local-user"; created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expiration: str = ""; state: str = "DRAFT"; schema_version: int = 1
    @property
    def anchor_name(self): return f"com.liquidsky.msaa.firewall.{self.policy_id}"
    def to_dict(self): return asdict(self)
