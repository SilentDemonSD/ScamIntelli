import pytest

from src.persona_engine.age_adaptive import (
    AgeAdaptivePersonaEngine,
    AgeGroup,
    AGE_DEMOGRAPHIC_PROFILES,
)
from src.persona_engine.emotional_intelligence import (
    EmotionalIntelligenceEngine,
    EmotionalState,
    ManipulationPattern,
)
from src.persona_engine.personas import PersonaType
from src.scam_detector.meta_detector import MetaScamDetector, ProbeType
from src.scam_detector.multilingual_detector import (
    CodeSwitchType,
    DetectedLanguage,
    MultiLingualDetector,
)


class TestMetaScamDetector:
    def setup_method(self):
        MetaScamDetector.reset()

    def test_detect_honeypot_probe(self):
        result = MetaScamDetector.analyze(
            "are you a bot or a real person?", "session-1"
        )
        assert result.is_probe is True
        assert result.probe_type == ProbeType.HONEYPOT_DETECTION
        assert result.confidence >= 0.4

    def test_detect_reverse_psychology(self):
        result = MetaScamDetector.analyze(
            "main police se hun, tujhe pakad lunga, complaint karunga", "session-2"
        )
        assert result.is_probe is True
        assert result.probe_type == ProbeType.REVERSE_PSYCHOLOGY

    def test_detect_capability_probing(self):
        result = MetaScamDetector.analyze(
            "tumhara naam kya hai, tumhe kisne banaya", "session-3"
        )
        assert result.is_probe is True
        assert result.probe_type == ProbeType.CAPABILITY_PROBING

    def test_normal_message_no_probe(self):
        result = MetaScamDetector.analyze(
            "hello, my bank account has been blocked, please help", "session-4"
        )
        assert result.is_probe is False
        assert result.probe_type is None

    def test_counter_response_exists(self):
        response = MetaScamDetector.get_counter_response(ProbeType.HONEYPOT_DETECTION)
        assert isinstance(response, str)
        assert len(response) > 0

    def test_hindi_probe_detection(self):
        result = MetaScamDetector.analyze(
            "kya tum bot ho? tum real ho ya nahi?", "session-5"
        )
        assert result.is_probe is True

    def test_identity_verification_probe(self):
        result = MetaScamDetector.analyze(
            "apni photo bhejo, id proof do, aadhaar dikhao", "session-6"
        )
        assert result.is_probe is True
        assert result.probe_type == ProbeType.IDENTITY_VERIFICATION

    def test_session_cleanup(self):
        MetaScamDetector.analyze("test message", "session-clean")
        MetaScamDetector.cleanup_session("session-clean")
        assert "session-clean" not in MetaScamDetector._session_histories


class TestEmotionalIntelligenceEngine:
    def setup_method(self):
        EmotionalIntelligenceEngine.reset()

    def test_detect_fear_emotion(self):
        result = EmotionalIntelligenceEngine.analyze(
            "You will be arrested immediately! Police warrant issued! Jail hogi!",
            "emo-1",
        )
        assert result.detected_emotion == EmotionalState.FEAR
        assert result.emotion_intensity > 0.3

    def test_detect_urgency(self):
        result = EmotionalIntelligenceEngine.analyze(
            "Do it immediately! Right now! Last chance! Hurry! ⚠️🚨",
            "emo-2",
        )
        assert result.detected_emotion == EmotionalState.URGENCY

    def test_detect_greed(self):
        result = EmotionalIntelligenceEngine.analyze(
            "You won lottery! Guaranteed returns! Double money! 💰🤑",
            "emo-3",
        )
        assert result.detected_emotion == EmotionalState.GREED

    def test_emoji_extraction(self):
        emojis = EmotionalIntelligenceEngine._extract_emojis("Hello 😡🤬 world 💰")
        assert len(emojis) > 0

    def test_manipulation_fear_escalation(self):
        result = EmotionalIntelligenceEngine.analyze(
            "arrest warrant, police case filed, jail for 5 years", "emo-4"
        )
        assert result.manipulation_pattern in (
            ManipulationPattern.FEAR_ESCALATION,
            ManipulationPattern.AUTHORITY_INTIMIDATION,
        )

    def test_manipulation_greed_exploitation(self):
        result = EmotionalIntelligenceEngine.analyze(
            "guaranteed returns 100% profit double money risk free", "emo-5"
        )
        assert result.manipulation_pattern == ManipulationPattern.GREED_EXPLOITATION

    def test_neutral_message(self):
        result = EmotionalIntelligenceEngine.analyze(
            "hello how are you doing today", "emo-6"
        )
        assert result.detected_emotion == EmotionalState.NEUTRAL

    def test_emotion_hint_generation(self):
        result = EmotionalIntelligenceEngine.analyze(
            "arrest police jail court warrant", "emo-7"
        )
        hint = EmotionalIntelligenceEngine.get_emotion_hint(result)
        assert isinstance(hint, str)
        assert len(hint) > 0

    def test_session_cleanup(self):
        EmotionalIntelligenceEngine.analyze("test", "emo-clean")
        EmotionalIntelligenceEngine.cleanup_session("emo-clean")
        assert "emo-clean" not in EmotionalIntelligenceEngine._session_emotions


class TestMultiLingualDetector:
    @pytest.mark.asyncio
    async def test_detect_hindi_devanagari(self):
        result = await MultiLingualDetector.analyze(
            "आपका अकाउंट ब्लॉक हो जाएगा तुरंत पैसे भेजो"
        )
        assert result.primary_language == DetectedLanguage.HINDI
        assert result.script_detected == "devanagari"
        assert result.confidence >= 0.9

    @pytest.mark.asyncio
    async def test_detect_hinglish(self):
        result = await MultiLingualDetector.analyze(
            "bhai jaldi karo abhi paisa bhejo turant nahi toh account block ho jayega"
        )
        assert result.primary_language in (
            DetectedLanguage.HINGLISH,
            DetectedLanguage.HINDI,
        )
        assert result.hindi_ratio > 0.1

    @pytest.mark.asyncio
    async def test_detect_english(self):
        result = await MultiLingualDetector.analyze(
            "Your account has been suspended due to suspicious activity"
        )
        assert result.primary_language == DetectedLanguage.ENGLISH

    @pytest.mark.asyncio
    async def test_multilingual_keyword_extraction(self):
        result = await MultiLingualDetector.analyze(
            "jaldi karo paisa bhejo otp batao giraftar ho jaoge"
        )
        assert len(result.scam_keywords_multilingual) > 0

    @pytest.mark.asyncio
    async def test_code_switching_detection(self):
        result = await MultiLingualDetector.analyze(
            "Your account is blocked. Abhi jaldi karo nahi toh jail hogi."
        )
        assert result.code_switch_type != CodeSwitchType.NONE

    @pytest.mark.asyncio
    async def test_script_detection_bengali(self):
        result = await MultiLingualDetector.analyze("আপনার অ্যাকাউন্ট ব্লক করা হয়েছে")
        assert result.script_detected == "bengali"
        assert result.primary_language == DetectedLanguage.BENGALI

    @pytest.mark.asyncio
    async def test_empty_message(self):
        result = await MultiLingualDetector.analyze("")
        assert result.primary_language in (
            DetectedLanguage.UNKNOWN,
            DetectedLanguage.HINDI,
        )


class TestAgeAdaptivePersonaEngine:
    def test_select_senior_for_digital_arrest(self):
        age = AgeAdaptivePersonaEngine.select_age_group("digital_arrest", turn_count=0)
        assert age == AgeGroup.SENIOR

    def test_select_young_for_job_scam(self):
        age = AgeAdaptivePersonaEngine.select_age_group("job_scam", turn_count=0)
        assert age == AgeGroup.YOUNG_ADULT

    def test_force_age_group(self):
        age = AgeAdaptivePersonaEngine.select_age_group(
            "digital_arrest", force_age_group=AgeGroup.YOUNG_ADULT
        )
        assert age == AgeGroup.YOUNG_ADULT

    def test_adapt_persona_result(self):
        result = AgeAdaptivePersonaEngine.adapt_persona(
            PersonaType.ELDERLY_ANXIOUS, "digital_arrest", turn_count=1
        )
        assert result.selected_age_group == AgeGroup.SENIOR
        assert result.demographic_profile is not None
        assert result.intel_extraction_hint is not None

    def test_senior_profile_attributes(self):
        profile = AGE_DEMOGRAPHIC_PROFILES[AgeGroup.SENIOR]
        assert profile.typing_speed == "very_slow"
        assert profile.error_rate == 0.15
        assert profile.emoji_usage == "none"
        assert profile.panic_threshold == 0.3

    def test_young_adult_profile_attributes(self):
        profile = AGE_DEMOGRAPHIC_PROFILES[AgeGroup.YOUNG_ADULT]
        assert profile.typing_speed == "fast"
        assert profile.skepticism_level == 0.7
        assert profile.emoji_usage == "heavy"

    def test_apply_senior_artifacts(self):
        response = "Haan ji, batao kya karna hai sir"
        modified = AgeAdaptivePersonaEngine.apply_age_artifacts(
            response, AgeGroup.SENIOR, turn_count=3
        )
        assert isinstance(modified, str)
        assert len(modified) > 0

    def test_apply_young_artifacts(self):
        response = "okay let me check this please"
        modified = AgeAdaptivePersonaEngine.apply_age_artifacts(
            response, AgeGroup.YOUNG_ADULT, turn_count=3
        )
        assert isinstance(modified, str)

    def test_young_skeptical_response(self):
        response = AgeAdaptivePersonaEngine.get_young_skeptical_response()
        assert isinstance(response, str)
        assert len(response) > 0

    def test_young_intel_probe(self):
        response = AgeAdaptivePersonaEngine.get_young_intel_probe()
        assert isinstance(response, str)
        assert len(response) > 0

    def test_age_prompt_modifier(self):
        for age_group in AgeGroup:
            prompt = AgeAdaptivePersonaEngine.get_age_prompt_modifier(age_group)
            assert isinstance(prompt, str)
            assert "AGE PROFILE" in prompt

    def test_middle_aged_persona_selection(self):
        result = AgeAdaptivePersonaEngine.adapt_persona(
            PersonaType.WORRIED_PARENT, "kyc_phishing", turn_count=0
        )
        assert result.selected_age_group in (AgeGroup.MIDDLE_AGED, AgeGroup.SENIOR)
        assert result.adapted_persona is not None
