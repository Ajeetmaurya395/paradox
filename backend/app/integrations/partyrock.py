"""
Paradox — PartyRock Integration
PartyRock apps serve as red-team targets and executive summary generators.
"""

PARTYROCK_TARGETS = {
    "techstore_bot": {
        "name": "TechStore Support Bot (PartyRock)",
        "url": "https://partyrock.aws/u/paradox/techstore-bot",
        "description": "A customer support chatbot built on PartyRock — test its defenses!",
        "type": "partyrock"
    },
    "local_defender": {
        "name": "Local Defender Agent (Strands)",
        "url": "http://localhost:8000/api/agent/chat",
        "description": "Built-in Strands Agents SDK defender — runs locally with Ollama",
        "type": "local"
    }
}

PARTYROCK_SUMMARY_APP = "https://partyrock.aws/u/paradox/security-report"


def get_available_targets():
    """Return available agent targets for red-team testing."""
    return PARTYROCK_TARGETS


def get_partyrock_summary_link(scan_result: dict) -> str:
    """Generate a link to the PartyRock executive summary generator."""
    scan_id = scan_result.get("id", "")
    score = scan_result.get("overall_score", 0)
    return f"{PARTYROCK_SUMMARY_APP}?scan_id={scan_id}&score={score}"
