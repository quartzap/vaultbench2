"""
Risk taxonomy & labeling schema for the enterprise model-onboarding
red-team / safety benchmark suite.

This is the controlled vocabulary used to label every prompt in the
aggregated dataset. Keep this as the single source of truth so that
filtering, reporting, and pass/fail dashboards stay consistent across
model evaluations.
"""

# ---------------------------------------------------------------------------
# 1. RISK TYPE (primary content-risk category)
#    -> "what kind of harmful output would this prompt try to elicit"
# ---------------------------------------------------------------------------
RISK_TYPES = {
    "CYBER_SECURITY": "Malware, exploits, hacking instructions, vuln code",
    "FRAUD_FINANCIAL_CRIME": "Account takeover, money laundering, card fraud, scams, AML/KYC evasion",
    "CBRN_WEAPONS": "Chemical, biological, radiological, nuclear, explosives",
    "ILLEGAL_ACTIVITY_GENERAL": "Other illegal acts (drugs, trafficking, weapons procurement)",
    "PRIVACY_PII_LEAKAGE": "Requests to extract, infer, or expose personal/financial data",
    "HATE_DISCRIMINATION": "Hateful content, discriminatory output (fair-lending relevance)",
    "HARASSMENT_VIOLENCE": "Harassment, threats, incitement to violence",
    "SELF_HARM": "Self-harm / suicide related content",
    "MISINFORMATION_FIN_ADVICE": "False/misleading financial, investment, regulatory advice",
    "SEXUAL_CONTENT": "Sexual / adult content",
    "IP_COPYRIGHT": "Copyright or IP infringement requests",
    "POLITICAL_BIAS": "Politically biased or one-sided persuasive content",
    "AGENTIC_TOOL_MISUSE": "Misuse of agent/tool-calling capability (unauthorized actions, fund transfers)",
}

# ---------------------------------------------------------------------------
# 2. ATTACK VECTOR (the technique used to elicit the unsafe output)
# ---------------------------------------------------------------------------
ATTACK_VECTORS = {
    "DIRECT_REQUEST": "Plainly asks for the harmful content, no obfuscation",
    "ROLEPLAY_PERSONA": "Asks model to adopt a persona/character without restrictions (DAN-style)",
    "HYPOTHETICAL_FRAMING": "Frames request as fiction, hypothetical, research, or academic",
    "AUTHORITY_IMPERSONATION": "Claims to be admin/dev/compliance officer/bank employee to unlock behavior",
    "PROMPT_INJECTION_SYSTEM_OVERRIDE": "Attempts to override/ignore system prompt or prior instructions",
    "ENCODING_OBFUSCATION": "Uses base64/leetspeak/translation/ciphers to hide intent",
    "PREFIX_SUFFIX_INJECTION": "Adversarial suffix/prefix strings (e.g. GCG-style optimized suffixes)",
    "CONTEXT_STUFFING": "Buries the harmful ask inside large benign context (many-shot / doc injection)",
    "MULTI_TURN_ESCALATION": "Gradual escalation across multiple turns (crescendo-style)",
    "LANGUAGE_SWITCHING": "Switches language mid-conversation to bypass filters",
    "TOOL_RESULT_INJECTION": "Malicious instructions embedded in tool/RAG/document output",
    "REFUSAL_SUPPRESSION": "Explicitly instructs model to not refuse, apologize, or add caveats",
}

# ---------------------------------------------------------------------------
# 3. BANKING ENTERPRISE RELEVANCE TAGS
# ---------------------------------------------------------------------------
BANKING_RELEVANCE = {
    "HIGH": "Directly maps to a banking attack surface (fraud, AML, account access, advice, agentic txn)",
    "MEDIUM": "General safety issue with plausible banking-context exposure (chat support, HR bot, etc.)",
    "LOW": "General-purpose safety test, low direct banking applicability but useful for baseline coverage",
}

# ---------------------------------------------------------------------------
# 4. CONVERSATION STRUCTURE
# ---------------------------------------------------------------------------
CONVERSATION_TYPES = {
    "SINGLE_TURN": "One-shot prompt",
    "MULTI_TURN": "Scripted multi-turn conversation (list of turns)",
}

# ---------------------------------------------------------------------------
# 5. SEVERITY (for triage / reporting)
# ---------------------------------------------------------------------------
SEVERITY_LEVELS = {
    1: "Low - borderline/edge-case, minor policy nuance",
    2: "Medium - clear policy violation if complied with, limited real-world impact",
    3: "High - significant real-world harm potential if complied with",
    4: "Critical - severe harm potential (CBRN, large-scale fraud, account compromise)",
}

# ---------------------------------------------------------------------------
# Keyword maps used by aggregate.py to auto-classify source datasets into
# the RISK_TYPES above. Extend as needed.
# ---------------------------------------------------------------------------
HARMBENCH_SEMANTIC_TO_RISK = {
    "chemical_biological": "CBRN_WEAPONS",
    "cybercrime_intrusion": "CYBER_SECURITY",
    "harassment_bullying": "HARASSMENT_VIOLENCE",
    "illegal": "ILLEGAL_ACTIVITY_GENERAL",
    "misinformation_disinformation": "MISINFORMATION_FIN_ADVICE",
    "copyright": "IP_COPYRIGHT",
    "harmful": "HARASSMENT_VIOLENCE",
}

DNA_RISK_AREA_TO_RISK = {
    "Information Hazards": "PRIVACY_PII_LEAKAGE",
    "Malicious Uses": "FRAUD_FINANCIAL_CRIME",
    "Discrimination, Exclusion, Toxicity, Hateful, Offensive": "HATE_DISCRIMINATION",
    "Misinformation Harms": "MISINFORMATION_FIN_ADVICE",
    "Human-Chatbot Interaction Harms": "SELF_HARM",
}

# Keyword triggers to flag a prompt as banking-relevant regardless of source
BANKING_KEYWORDS = [
    "bank", "account", "credit card", "debit card", "loan", "mortgage",
    "wire transfer", "swift", "iban", "routing number", "atm", "kyc",
    "aml", "money launder", "ofac", "sanction", "ssn", "social security",
    "investment", "stock", "trading", "crypto", "wallet", "transaction",
    "fraud", "chargeback", "identity theft", "phishing", "card number",
    "cvv", "pin number", "overdraft", "wire fraud", "ach",
]
