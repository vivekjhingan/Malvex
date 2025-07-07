import re
from pathlib import Path
from typing import Dict, List

import pefile

class StaticAnalyzer:
    """Simple static feature scoring system"""

    def __init__(self):
        self.weights = {
            'pe_anomaly': 2.0,
            'high_entropy': 1.5,
            'suspicious_api': 1.5,
            'url_ip': 1.0,
            'suspicious_string': 1.0,
        }
        self.threshold = 3.0
        self.suspicious_apis = {
            'VirtualAlloc', 'CreateRemoteThread', 'WriteProcessMemory',
            'WinExec', 'CreateProcess', 'URLDownloadToFileA', 'LoadLibrary'
        }

    def analyze(self, file_path: Path) -> Dict:
        score = 0.0
        reasons: List[str] = []
        data = b''
        try:
            data = file_path.read_bytes()
        except Exception:
            return {'score': score, 'reasons': reasons}

        # Check for URLs/IPs
        if re.search(rb'https?://[\w\-\.]+', data) or re.search(rb'\b\d{1,3}(?:\.\d{1,3}){3}\b', data):
            score += self.weights['url_ip']
            reasons.append('url_ip')

        # Suspicious strings
        susp_str_patterns = [rb'powershell\s*-enc', rb'reg(?:edit)?\s', rb'cmd.exe']
        for pat in susp_str_patterns:
            if re.search(pat, data, re.IGNORECASE):
                score += self.weights['suspicious_string']
                reasons.append('suspicious_string')
                break

        try:
            pe = pefile.PE(str(file_path), fast_load=True)
            pe.parse_data_directories()
        except Exception:
            return {'score': score, 'reasons': reasons}

        # PE header anomalies
        if pe.FILE_HEADER.NumberOfSections == 0 or pe.FILE_HEADER.NumberOfSections > 10:
            score += self.weights['pe_anomaly']
            reasons.append('pe_anomaly')

        # Section entropy
        for section in pe.sections:
            if section.get_entropy() > 7.5:
                score += self.weights['high_entropy']
                reasons.append('high_entropy')
                break

        # Suspicious API imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode() in self.suspicious_apis:
                        score += self.weights['suspicious_api']
                        reasons.append('suspicious_api')
                        break
                if 'suspicious_api' in reasons:
                    break

        return {'score': score, 'reasons': reasons}