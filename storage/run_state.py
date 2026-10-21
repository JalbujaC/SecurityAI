import json
from pathlib import Path
import stat
from scope.targets import TargetManager

class RunStateStore:
    def __init__(self, path: str):
        self.path = Path(path)

    def save(self, target_manager: TargetManager) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.path.write_text(
            json.dumps(target_manager.export_state(), indent=2),
            encoding="utf-8"
        )

    def load(self, target_manager: TargetManager) -> None:
        if not self.path.exists():
            return

        state = json.loads(
            self.path.read_text(
                encoding="utf-8"
            )
        )

        target_manager.import_state(
            state
        )
