from kirabridge.terminal_manager import TerminalManager


class ProcessManager:
    """Inspect and terminate only process groups created by this bridge instance."""

    def __init__(self, terminal: TerminalManager):
        self.terminal = terminal

    def list(self, principal: str) -> dict:
        return {
            "processes": [
                self.terminal.inspect(principal, key)
                for key, session in self.terminal.sessions.items()
                if session.principal == principal
            ]
        }
