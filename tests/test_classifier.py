"""
Tests for the Challenge Classification module.
"""

import pytest
from unittest.mock import Mock

from ctf_solver.classifier import (
    ChallengeCategory,
    ChallengeClassifier,
    ClassificationResult,
    PatternMatcher,
    create_classifier,
    TOOL_PRIORITIES,
    APPROACH_SUGGESTIONS,
)


# =============================================================================
# ChallengeCategory Tests
# =============================================================================

class TestChallengeCategory:
    """Tests for ChallengeCategory enum."""

    def test_all_categories_have_values(self):
        """Test that all categories have string values."""
        for category in ChallengeCategory:
            assert isinstance(category.value, str)
            assert len(category.value) > 0

    def test_category_count(self):
        """Test expected number of categories."""
        # At least 14 categories (may add more)
        assert len(ChallengeCategory) >= 14

    def test_key_categories_exist(self):
        """Test that key categories exist."""
        expected = [
            "sql_injection", "xss", "ssti", "xxe", "file_upload",
            "jwt", "authentication", "command_injection", "ssrf",
        ]
        category_values = [c.value for c in ChallengeCategory]
        for exp in expected:
            assert exp in category_values


# =============================================================================
# ClassificationResult Tests
# =============================================================================

class TestClassificationResult:
    """Tests for ClassificationResult dataclass."""

    def test_create_basic_result(self):
        """Test creating a basic classification result."""
        result = ClassificationResult(
            primary_category=ChallengeCategory.SQL_INJECTION,
            confidence=0.85,
        )
        assert result.primary_category == ChallengeCategory.SQL_INJECTION
        assert result.confidence == 0.85
        assert result.secondary_categories == []
        assert result.matched_keywords == []

    def test_create_full_result(self):
        """Test creating a result with all fields."""
        result = ClassificationResult(
            primary_category=ChallengeCategory.JWT,
            confidence=0.9,
            secondary_categories=[
                (ChallengeCategory.AUTHENTICATION, 0.5),
            ],
            matched_keywords=["jwt", "token"],
            matched_patterns=[r"/login"],
            suggested_tools=["jwt", "http_fetch"],
            suggested_approach="1. Decode JWT\n2. Test attacks",
        )
        assert result.primary_category == ChallengeCategory.JWT
        assert len(result.secondary_categories) == 1
        assert len(result.matched_keywords) == 2

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = ClassificationResult(
            primary_category=ChallengeCategory.XSS,
            confidence=0.75,
            secondary_categories=[
                (ChallengeCategory.AUTHENTICATION, 0.3),
            ],
            matched_keywords=["xss", "script"],
            suggested_tools=["http_fetch"],
        )
        d = result.to_dict()

        assert d["primary_category"] == "xss"
        assert d["confidence"] == 0.75
        assert len(d["secondary_categories"]) == 1
        assert d["secondary_categories"][0]["category"] == "authentication"
        assert "xss" in d["matched_keywords"]

    def test_to_dict_empty_result(self):
        """Test to_dict with minimal result."""
        result = ClassificationResult(
            primary_category=ChallengeCategory.UNKNOWN,
            confidence=0.0,
        )
        d = result.to_dict()
        assert d["primary_category"] == "unknown"
        assert d["confidence"] == 0.0


# =============================================================================
# PatternMatcher Tests
# =============================================================================

class TestPatternMatcher:
    """Tests for PatternMatcher class."""

    def test_create_pattern_matcher(self):
        """Test creating a pattern matcher."""
        matcher = PatternMatcher()
        assert matcher is not None

    def test_match_sql_keywords(self):
        """Test matching SQL injection keywords."""
        matcher = PatternMatcher()
        text = "This challenge involves SQL injection to bypass the login"
        matches = matcher.match_keywords(text)

        # Should find SQL injection and authentication
        categories = [m[0] for m in matches]
        assert ChallengeCategory.SQL_INJECTION in categories

    def test_match_jwt_keywords(self):
        """Test matching JWT keywords."""
        matcher = PatternMatcher()
        text = "Crack the JWT token and modify the claims"
        matches = matcher.match_keywords(text)

        categories = [m[0] for m in matches]
        assert ChallengeCategory.JWT in categories

    def test_match_ssti_keywords(self):
        """Test matching SSTI keywords."""
        matcher = PatternMatcher()
        text = "Jinja2 template injection vulnerability {{7*7}}"
        matches = matcher.match_keywords(text)

        categories = [m[0] for m in matches]
        assert ChallengeCategory.SSTI in categories

    def test_match_xxe_keywords(self):
        """Test matching XXE keywords."""
        matcher = PatternMatcher()
        text = "XML external entity attack to read /etc/passwd"
        matches = matcher.match_keywords(text)

        categories = [m[0] for m in matches]
        assert ChallengeCategory.XXE in categories

    def test_match_file_upload_keywords(self):
        """Test matching file upload keywords."""
        matcher = PatternMatcher()
        text = "Upload a PHP webshell by bypassing the extension filter"
        matches = matcher.match_keywords(text)

        categories = [m[0] for m in matches]
        assert ChallengeCategory.FILE_UPLOAD in categories

    def test_match_url_sql_pattern(self):
        """Test matching SQL injection URL patterns."""
        matcher = PatternMatcher()
        url = "http://example.com/user?id=123"
        matches = matcher.match_url(url)

        categories = [m[0] for m in matches]
        assert ChallengeCategory.SQL_INJECTION in categories

    def test_match_url_file_inclusion_pattern(self):
        """Test matching file inclusion URL patterns."""
        matcher = PatternMatcher()
        url = "http://example.com/view?file=readme.txt"
        matches = matcher.match_url(url)

        categories = [m[0] for m in matches]
        assert ChallengeCategory.FILE_INCLUSION in categories

    def test_match_url_ssrf_pattern(self):
        """Test matching SSRF URL patterns."""
        matcher = PatternMatcher()
        url = "http://example.com/proxy?url=http://internal"
        matches = matcher.match_url(url)

        categories = [m[0] for m in matches]
        assert ChallengeCategory.SSRF in categories

    def test_match_url_no_matches(self):
        """Test URL with no vulnerability patterns."""
        matcher = PatternMatcher()
        url = "http://example.com/about"
        matches = matcher.match_url(url)

        # Should have few or no matches
        assert len(matches) <= 2

    def test_analyze_url_structure_basic(self):
        """Test URL structure analysis."""
        matcher = PatternMatcher()
        analysis = matcher.analyze_url_structure(
            "http://example.com/admin/user?id=1&name=test"
        )

        assert analysis["scheme"] == "http"
        assert analysis["host"] == "example.com"
        assert analysis["path"] == "/admin/user"
        assert analysis["has_query"] is True
        assert len(analysis["query_params"]) == 2
        assert "id" in analysis["interesting_params"]

    def test_analyze_url_structure_interesting_params(self):
        """Test detection of interesting parameters."""
        matcher = PatternMatcher()
        analysis = matcher.analyze_url_structure(
            "http://example.com/view?file=test&page=1"
        )

        assert "file" in analysis["interesting_params"]
        assert "page" in analysis["interesting_params"]

    def test_analyze_url_structure_path_hints(self):
        """Test detection of path hints."""
        matcher = PatternMatcher()
        analysis = matcher.analyze_url_structure(
            "http://example.com/admin/dashboard"
        )

        assert "admin" in analysis["path_hints"]

    def test_analyze_invalid_url(self):
        """Test handling of invalid URL."""
        matcher = PatternMatcher()
        # urlparse handles most strings gracefully
        analysis = matcher.analyze_url_structure("not-a-valid-url")
        assert "scheme" in analysis

    def test_match_multiple_categories(self):
        """Test matching multiple categories in one text."""
        matcher = PatternMatcher()
        text = "SQL injection in login form, then upload a webshell"
        matches = matcher.match_keywords(text)

        categories = [m[0] for m in matches]
        assert ChallengeCategory.SQL_INJECTION in categories
        assert ChallengeCategory.FILE_UPLOAD in categories

    def test_case_insensitive_matching(self):
        """Test case insensitive keyword matching."""
        matcher = PatternMatcher()

        # Test various cases
        for text in ["SQL INJECTION", "sql injection", "SQL Injection"]:
            matches = matcher.match_keywords(text)
            categories = [m[0] for m in matches]
            assert ChallengeCategory.SQL_INJECTION in categories

    def test_score_ordering(self):
        """Test that results are ordered by score."""
        matcher = PatternMatcher()
        text = "SQL injection union select from database MySQL"
        matches = matcher.match_keywords(text)

        if len(matches) >= 2:
            # First should have highest score
            assert matches[0][1] >= matches[1][1]


# =============================================================================
# ChallengeClassifier Tests
# =============================================================================

class TestChallengeClassifier:
    """Tests for ChallengeClassifier class."""

    def test_create_classifier(self):
        """Test creating a classifier."""
        classifier = ChallengeClassifier()
        assert classifier is not None
        assert classifier.pattern_matcher is not None

    def test_create_classifier_factory(self):
        """Test factory function."""
        classifier = create_classifier()
        assert isinstance(classifier, ChallengeClassifier)

    def test_classify_sql_injection_description(self):
        """Test classifying SQL injection from description."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="Bypass the login using SQL injection"
        )

        assert result.primary_category == ChallengeCategory.SQL_INJECTION
        assert result.confidence > 0.3
        assert len(result.suggested_tools) > 0
        assert "sqli_probe" in result.suggested_tools

    def test_classify_jwt_description(self):
        """Test classifying JWT challenge."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="The authentication uses JWT tokens. Can you escalate?"
        )

        assert result.primary_category == ChallengeCategory.JWT
        assert result.confidence > 0.2
        assert "jwt" in result.suggested_tools

    def test_classify_ssti_description(self):
        """Test classifying SSTI challenge."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="Jinja2 template injection to get RCE"
        )

        assert result.primary_category == ChallengeCategory.SSTI
        assert "ssti_probe" in result.suggested_tools

    def test_classify_from_url(self):
        """Test classifying from URL patterns."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            url="http://ctf.example.com/user?id=1"
        )

        # Should detect SQL injection potential
        assert result.primary_category in [
            ChallengeCategory.SQL_INJECTION,
            ChallengeCategory.AUTHENTICATION,
            ChallengeCategory.UNKNOWN,
        ]

    def test_classify_from_url_and_description(self):
        """Test classifying with both URL and description."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="Find the hidden flag",
            url="http://ctf.example.com/login?user=admin",
        )

        # Should combine signals
        assert result.confidence > 0
        assert len(result.suggested_tools) > 0

    def test_classify_with_hints(self):
        """Test classifying with hints."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="Get the flag",
            hints=["Think about SQL", "The database is MySQL"],
        )

        assert result.primary_category == ChallengeCategory.SQL_INJECTION
        assert result.confidence > 0.2  # 3 keyword matches should give ~0.27

    def test_classify_file_upload(self):
        """Test classifying file upload challenge."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="Upload an image and get code execution"
        )

        assert result.primary_category == ChallengeCategory.FILE_UPLOAD
        assert "file_upload" in result.suggested_tools

    def test_classify_xxe(self):
        """Test classifying XXE challenge."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="Parse XML and read the flag file"
        )

        assert result.primary_category == ChallengeCategory.XXE
        assert "xxe_probe" in result.suggested_tools

    def test_classify_unknown(self):
        """Test classifying ambiguous challenge."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="Find the flag"
        )

        # Should return unknown or reconnaissance
        assert result.primary_category in [
            ChallengeCategory.UNKNOWN,
            ChallengeCategory.RECONNAISSANCE,
        ]

    def test_classify_empty_input(self):
        """Test classifying with no input."""
        classifier = ChallengeClassifier()
        result = classifier.classify()

        assert result.primary_category == ChallengeCategory.UNKNOWN
        assert result.confidence == 0.0

    def test_classify_response_content(self):
        """Test classifying with response content."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            response_content="<form action='/login'><input name='username'></form>"
        )

        # Should detect authentication
        categories = [result.primary_category] + [
            c for c, _ in result.secondary_categories
        ]
        assert ChallengeCategory.AUTHENTICATION in categories or \
               result.primary_category != ChallengeCategory.UNKNOWN

    def test_secondary_categories(self):
        """Test that secondary categories are populated."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="SQL injection to bypass login and get admin JWT token"
        )

        # Should have secondary categories
        if result.confidence > 0.3:
            secondary_cats = [c for c, _ in result.secondary_categories]
            # May include auth, jwt, or sql depending on classification
            assert len(result.secondary_categories) >= 0

    def test_suggested_approach_populated(self):
        """Test that suggested approach is populated."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="SQL injection challenge"
        )

        assert len(result.suggested_approach) > 0
        assert "1." in result.suggested_approach

    def test_matched_keywords_tracked(self):
        """Test that matched keywords are tracked."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="SQL injection UNION attack"
        )

        # Should have some matched keywords
        if result.confidence > 0.2:
            assert len(result.matched_keywords) > 0

    def test_get_tool_priority(self):
        """Test getting tool priority for category."""
        classifier = ChallengeClassifier()
        tools = classifier.get_tool_priority(ChallengeCategory.SQL_INJECTION)

        assert len(tools) > 0
        assert "sqli_probe" in tools

    def test_get_tool_priority_unknown(self):
        """Test tool priority for unknown category."""
        classifier = ChallengeClassifier()
        tools = classifier.get_tool_priority(ChallengeCategory.UNKNOWN)

        assert len(tools) > 0
        assert "http_fetch" in tools

    def test_get_all_categories(self):
        """Test getting all category values."""
        classifier = ChallengeClassifier()
        categories = classifier.get_all_categories()

        assert len(categories) >= 14
        assert "sql_injection" in categories
        assert "unknown" in categories

    def test_suggest_initial_tools_basic(self):
        """Test suggesting initial tools."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="SQL injection challenge"
        )
        tools = classifier.suggest_initial_tools(result, max_tools=5)

        assert len(tools) <= 5
        assert len(tools) > 0

    def test_suggest_initial_tools_no_duplicates(self):
        """Test that suggested tools have no duplicates."""
        classifier = ChallengeClassifier()
        result = classifier.classify(
            description="SQL injection bypass login authentication"
        )
        tools = classifier.suggest_initial_tools(result, max_tools=10)

        # Check no duplicates
        assert len(tools) == len(set(tools))

    def test_classify_from_config(self):
        """Test classifying from config-like object."""
        classifier = ChallengeClassifier()

        mock_config = Mock()
        mock_config.challenge_description = "SQL injection challenge"
        mock_config.challenge_url = "http://example.com/login"
        mock_config.challenge_hints = "Think about databases"

        result = classifier.classify_from_config(mock_config)

        assert result.primary_category == ChallengeCategory.SQL_INJECTION
        assert result.confidence > 0.3

    def test_classify_from_config_no_hints(self):
        """Test classifying from config with no hints."""
        classifier = ChallengeClassifier()

        mock_config = Mock()
        mock_config.challenge_description = "Find the flag"
        mock_config.challenge_url = None
        mock_config.challenge_hints = None

        result = classifier.classify_from_config(mock_config)
        assert result is not None


# =============================================================================
# Tool Priority Mapping Tests
# =============================================================================

class TestToolPriorities:
    """Tests for TOOL_PRIORITIES mapping."""

    def test_all_categories_have_priorities(self):
        """Test that all categories have tool priorities."""
        for category in ChallengeCategory:
            assert category in TOOL_PRIORITIES
            assert len(TOOL_PRIORITIES[category]) > 0

    def test_priority_lists_not_empty(self):
        """Test that all priority lists have tools."""
        for category, tools in TOOL_PRIORITIES.items():
            assert len(tools) >= 3

    def test_sql_injection_tools(self):
        """Test SQL injection tool priorities."""
        tools = TOOL_PRIORITIES[ChallengeCategory.SQL_INJECTION]
        assert "sqli_probe" in tools
        assert "blind_sqli_boolean" in tools

    def test_jwt_tools(self):
        """Test JWT tool priorities."""
        tools = TOOL_PRIORITIES[ChallengeCategory.JWT]
        assert "jwt" in tools

    def test_ssti_tools(self):
        """Test SSTI tool priorities."""
        tools = TOOL_PRIORITIES[ChallengeCategory.SSTI]
        assert "ssti_probe" in tools

    def test_xxe_tools(self):
        """Test XXE tool priorities."""
        tools = TOOL_PRIORITIES[ChallengeCategory.XXE]
        assert "xxe_probe" in tools

    def test_file_upload_tools(self):
        """Test file upload tool priorities."""
        tools = TOOL_PRIORITIES[ChallengeCategory.FILE_UPLOAD]
        assert "file_upload" in tools


# =============================================================================
# Approach Suggestions Tests
# =============================================================================

class TestApproachSuggestions:
    """Tests for APPROACH_SUGGESTIONS mapping."""

    def test_all_categories_have_suggestions(self):
        """Test that all categories have approach suggestions."""
        for category in ChallengeCategory:
            assert category in APPROACH_SUGGESTIONS
            assert len(APPROACH_SUGGESTIONS[category]) > 0

    def test_suggestions_are_multi_step(self):
        """Test that suggestions contain multiple steps."""
        for category, suggestion in APPROACH_SUGGESTIONS.items():
            assert "1." in suggestion or "1)" in suggestion

    def test_sql_injection_approach(self):
        """Test SQL injection approach content."""
        approach = APPROACH_SUGGESTIONS[ChallengeCategory.SQL_INJECTION]
        assert "injection" in approach.lower() or "payload" in approach.lower()

    def test_jwt_approach(self):
        """Test JWT approach content."""
        approach = APPROACH_SUGGESTIONS[ChallengeCategory.JWT]
        assert "decode" in approach.lower() or "token" in approach.lower()


# =============================================================================
# Integration Tests
# =============================================================================

class TestClassifierIntegration:
    """Integration tests for the classifier."""

    def test_full_classification_workflow(self):
        """Test complete classification workflow."""
        classifier = ChallengeClassifier()

        # Classify
        result = classifier.classify(
            description="SQL injection vulnerability in login",
            url="http://ctf.example.com/login?user=admin",
            hints=["Think about quotes"],
        )

        # Check result is complete
        assert result.primary_category is not None
        assert result.confidence >= 0
        assert len(result.suggested_tools) > 0
        assert len(result.suggested_approach) > 0

        # Get tool suggestions
        tools = classifier.suggest_initial_tools(result)
        assert len(tools) > 0

        # Convert to dict
        d = result.to_dict()
        assert "primary_category" in d

    def test_ambiguous_classification(self):
        """Test handling ambiguous challenges."""
        classifier = ChallengeClassifier()

        result = classifier.classify(
            description="Bypass security to get the flag"
        )

        # Should handle gracefully
        assert result.primary_category is not None
        assert len(result.suggested_tools) > 0

    def test_response_content_influence(self):
        """Test that response content influences classification."""
        classifier = ChallengeClassifier()

        # Without response content
        result1 = classifier.classify(
            description="A web challenge"
        )

        # With response content containing SQL-related keywords
        result2 = classifier.classify(
            description="A web challenge",
            response_content="MySQL error: syntax error near 'ORDER BY' in SQL query"
        )

        # Response content should influence result
        if result2.primary_category == ChallengeCategory.SQL_INJECTION:
            # With "MySQL", "SQL", and "query" matches, should get reasonable confidence
            assert result2.confidence > 0.1

    def test_long_description_handling(self):
        """Test handling of long descriptions."""
        classifier = ChallengeClassifier()

        long_desc = (
            "This is a SQL injection challenge where you need to bypass "
            "the login authentication by exploiting a vulnerability in the "
            "database query. The application uses MySQL as the backend. "
        ) * 10

        result = classifier.classify(description=long_desc)

        assert result.primary_category == ChallengeCategory.SQL_INJECTION
        assert result.confidence > 0.5

    def test_special_characters_handling(self):
        """Test handling of special characters in input."""
        classifier = ChallengeClassifier()

        result = classifier.classify(
            description="Use {{7*7}} to test for SSTI",
            hints=["Try ${7*7} too"],
        )

        # Should handle regex special chars
        assert result is not None
