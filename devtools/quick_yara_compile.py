# devtools/quick_yara_compile.py  (optional helper)
from pathlib import Path
from maldefender.app_logger import Logger
from maldefender.yara_scanner import YaraScanner

if __name__ == "__main__":
    log = Logger()
    ys = YaraScanner(log)
    sample = Path(__file__)  # any file
    matches, err = ys.scan_file(sample)
    print("err:", err)
    for m in matches:
        print(m.to_dict())
