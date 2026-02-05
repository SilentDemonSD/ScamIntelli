import hashlib
import hmac
import secrets
import time
import random
import re
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class RequestFingerprint:
    client_hash: str
    timestamp: int
    request_id: str
    is_suspicious: bool


class TamperProofMiddleware:
    
    _instance = None
    _request_history: Dict[str, list] = {}
    _blocked_patterns: set = set()
    
    HONEYPOT_DETECTION_PATTERNS = frozenset({
        r'honeypot', r'honey.?pot', r'scam.?detect', r'fraud.?detect',
        r'test.?api', r'api.?test', r'bot.?detect', r'anti.?fraud',
        r'trap', r'bait', r'decoy', r'fake.?user', r'simulation'
    })
    
    SUSPICIOUS_HEADERS = frozenset({
        'x-honeypot', 'x-bot-detection', 'x-test-mode', 'x-debug',
        'x-simulation', 'x-trap', 'honeypot-id', 'test-request'
    })
    
    BOT_USER_AGENTS = frozenset({
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
        'httpx', 'aiohttp', 'postman', 'insomnia', 'test', 'automated'
    })
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @staticmethod
    def generate_request_id() -> str:
        timestamp = int(time.time() * 1000)
        random_part = secrets.token_hex(8)
        return f"req_{timestamp}_{random_part}"
    
    @staticmethod
    def compute_client_hash(
        ip_address: str,
        user_agent: str,
        session_id: str
    ) -> str:
        data = f"{ip_address}:{user_agent}:{session_id}".encode()
        return hashlib.sha256(data).hexdigest()[:16]
    
    def detect_honeypot_probe(
        self,
        message: str,
        headers: Dict[str, str]
    ) -> Tuple[bool, str]:
        message_lower = message.lower()
        
        for pattern in self.HONEYPOT_DETECTION_PATTERNS:
            if re.search(pattern, message_lower):
                return True, "pattern_match"
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        for suspicious_header in self.SUSPICIOUS_HEADERS:
            if suspicious_header in headers_lower:
                return True, "suspicious_header"
        
        user_agent = headers_lower.get('user-agent', '')
        for bot_pattern in self.BOT_USER_AGENTS:
            if bot_pattern in user_agent:
                return True, "bot_user_agent"
        
        return False, ""
    
    def analyze_request_pattern(
        self,
        client_hash: str,
        current_time: float
    ) -> bool:
        if client_hash not in self._request_history:
            self._request_history[client_hash] = []
        
        history = self._request_history[client_hash]
        history.append(current_time)
        
        history[:] = [t for t in history if current_time - t < 60]
        
        if len(history) > 30:
            return True
        
        if len(history) >= 5:
            intervals = [history[i] - history[i-1] for i in range(1, len(history))]
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                if avg_interval < 0.5:
                    return True
                variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                if variance < 0.01 and len(intervals) >= 5:
                    return True
        
        return False
    
    def fingerprint_request(
        self,
        ip_address: str,
        user_agent: str,
        session_id: str,
        message: str,
        headers: Dict[str, str]
    ) -> RequestFingerprint:
        client_hash = self.compute_client_hash(ip_address, user_agent, session_id)
        current_time = time.time()
        request_id = self.generate_request_id()
        
        is_probe, _ = self.detect_honeypot_probe(message, headers)
        is_pattern_suspicious = self.analyze_request_pattern(client_hash, current_time)
        
        return RequestFingerprint(
            client_hash=client_hash,
            timestamp=int(current_time * 1000),
            request_id=request_id,
            is_suspicious=is_probe or is_pattern_suspicious
        )


class ResponseObfuscator:
    
    HUMAN_TIMING_PATTERNS = {
        'fast_typer': (50, 150),
        'normal_typer': (100, 300),
        'slow_typer': (200, 500),
        'elderly': (300, 800),
        'distracted': (500, 2000)
    }
    
    FILLER_PHRASES = (
        "hmm", "uh", "umm", "well", "so", "actually", "basically",
        "you know", "I mean", "like", "okay so"
    )
    
    HINDI_FILLERS = (
        "matlab", "haan", "accha", "woh", "arre", "dekho", "suno",
        "bolo", "kya", "thik hai"
    )
    
    TYPO_MAP = {
        'a': ['s', 'q', 'z'],
        'e': ['w', 'r', 'd'],
        'i': ['u', 'o', 'k'],
        'o': ['i', 'p', 'l'],
        'n': ['m', 'b', 'h'],
        't': ['r', 'y', 'g'],
        's': ['a', 'd', 'w']
    }
    
    @classmethod
    def add_human_delay(cls, persona_type: str) -> float:
        if 'elderly' in persona_type.lower() or 'senior' in persona_type.lower():
            pattern = cls.HUMAN_TIMING_PATTERNS['elderly']
        elif 'tech_naive' in persona_type.lower() or 'rural' in persona_type.lower():
            pattern = cls.HUMAN_TIMING_PATTERNS['slow_typer']
        elif 'professional' in persona_type.lower() or 'student' in persona_type.lower():
            pattern = cls.HUMAN_TIMING_PATTERNS['fast_typer']
        else:
            pattern = cls.HUMAN_TIMING_PATTERNS['normal_typer']
        
        base_delay = random.randint(pattern[0], pattern[1])
        jitter = random.randint(-50, 50)
        return max(50, base_delay + jitter) / 1000.0
    
    @classmethod
    def add_typing_artifacts(cls, text: str, error_rate: float = 0.02) -> str:
        if random.random() > 0.3:
            return text
        
        chars = list(text)
        for i in range(len(chars)):
            if random.random() < error_rate and chars[i].lower() in cls.TYPO_MAP:
                if random.random() < 0.7:
                    typo = random.choice(cls.TYPO_MAP[chars[i].lower()])
                    chars[i] = typo if chars[i].islower() else typo.upper()
        
        return ''.join(chars)
    
    @classmethod
    def humanize_response(
        cls,
        response: str,
        persona_type: str,
        add_fillers: bool = True
    ) -> str:
        if add_fillers and random.random() < 0.2:
            if 'hindi' in persona_type.lower() or random.random() < 0.5:
                filler = random.choice(cls.HINDI_FILLERS)
            else:
                filler = random.choice(cls.FILLER_PHRASES)
            response = f"{filler}, {response}"
        
        if random.random() < 0.15:
            response = response.rstrip('.!?') + random.choice(['...', '..', '.'])
        
        if random.random() < 0.1:
            words = response.split()
            if len(words) > 3:
                idx = random.randint(1, len(words) - 1)
                words.insert(idx, words[idx])
                response = ' '.join(words)
        
        return response


class HeaderSanitizer:
    
    STANDARD_HEADERS = frozenset({
        'content-type', 'content-length', 'accept', 'accept-language',
        'accept-encoding', 'connection', 'host', 'origin', 'referer',
        'user-agent', 'x-api-key', 'authorization', 'x-request-id',
        'x-forwarded-for', 'x-real-ip'
    })
    
    @classmethod
    def sanitize_outgoing_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        sanitized = {}
        
        safe_headers = {
            'Content-Type': 'application/json',
            'X-Request-ID': TamperProofMiddleware.generate_request_id(),
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff'
        }
        
        sanitized.update(safe_headers)
        return sanitized
    
    @classmethod
    def filter_incoming_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        filtered = {}
        for key, value in headers.items():
            if key.lower() in cls.STANDARD_HEADERS:
                filtered[key] = value[:500]
        return filtered


class AntiFingerprinting:
    
    RESPONSE_VARIATIONS = {
        'error_messages': [
            "Something went wrong",
            "Unable to process",
            "Please try again",
            "Request failed",
            "Service temporarily unavailable"
        ],
        'success_status': ['success', 'ok', 'processed', 'completed'],
        'timing_variance': (0.1, 0.5)
    }
    
    @classmethod
    def randomize_error_response(cls) -> str:
        return random.choice(cls.RESPONSE_VARIATIONS['error_messages'])
    
    @classmethod
    def add_response_jitter(cls) -> float:
        base = random.uniform(*cls.RESPONSE_VARIATIONS['timing_variance'])
        return base + random.random() * 0.1
    
    @classmethod
    def mask_internal_state(cls, response: Dict[str, Any]) -> Dict[str, Any]:
        masked = response.copy()
        
        fields_to_remove = [
            'internal_id', 'processing_time', 'server_id', 'version',
            'debug', 'trace', 'stack', 'internal_error'
        ]
        
        for field in fields_to_remove:
            masked.pop(field, None)
        
        return masked


def create_tamper_proof_response(
    response_data: Dict[str, Any],
    persona_type: str = "default"
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    masked_response = AntiFingerprinting.mask_internal_state(response_data)
    
    if 'reply' in masked_response:
        masked_response['reply'] = ResponseObfuscator.humanize_response(
            masked_response['reply'],
            persona_type
        )
    
    headers = HeaderSanitizer.sanitize_outgoing_headers({})
    
    return masked_response, headers


def validate_incoming_request(
    ip_address: str,
    user_agent: str,
    session_id: str,
    message: str,
    headers: Dict[str, str]
) -> Tuple[bool, Optional[str], RequestFingerprint]:
    middleware = TamperProofMiddleware()
    
    filtered_headers = HeaderSanitizer.filter_incoming_headers(headers)
    
    fingerprint = middleware.fingerprint_request(
        ip_address, user_agent, session_id, message, filtered_headers
    )
    
    if fingerprint.is_suspicious:
        return False, "suspicious_activity", fingerprint
    
    return True, None, fingerprint
