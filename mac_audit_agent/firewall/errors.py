class FirewallError(ValueError):
    def __init__(self, code: str, message: str, *, networking_changed: bool = False):
        super().__init__(f"{code}: {message}"); self.code = code; self.networking_changed = networking_changed
