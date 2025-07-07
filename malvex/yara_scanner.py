import os
from pathlib import Path
from typing import List

import yara

class YaraScanner:
    """Compile and run YARA rules"""

    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self.rules = self._compile_rules()

    def _compile_rules(self):
        rule_files = {}
        for path in self.rules_dir.glob('*.yar*'):
            rule_files[path.stem] = str(path)
        if rule_files:
            return yara.compile(filepaths=rule_files)
        return None

    def scan_file(self, file_path: Path) -> List[str]:
        if not self.rules:
            return []
        try:
            matches = self.rules.match(str(file_path))
            return [m.rule for m in matches]
        except Exception:
            return []