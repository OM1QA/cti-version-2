"""Confidence scoring utilities."""
from ..constants import SOURCE_CONFIDENCE

def calculate_confidence_score(source, base_confidence=None, days_old=0, corroboration_count=0):
    """Calculate overall confidence score based on source, age, and corroboration"""
    if base_confidence is None:
        base_confidence = SOURCE_CONFIDENCE.get(source, 0.70)

    # Age factor: newer data gets higher confidence
    if days_old <= 1:
        age_factor = 1.0
    elif days_old <= 7:
        age_factor = 0.95
    elif days_old <= 30:
        age_factor = 0.90
    elif days_old <= 90:
        age_factor = 0.85
    else:
        age_factor = 0.80

    # Corroboration factor: multiple sources increase confidence
    corroboration_factor = min(1.0 + (corroboration_count * 0.05), 1.20)

    final_confidence = base_confidence * age_factor * corroboration_factor
    return min(final_confidence, 1.0)
