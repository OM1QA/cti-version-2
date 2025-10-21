"""Base ingester class."""
import pandas as pd

class BaseIngester:
    """Base class for threat intelligence ingesters"""
    def __init__(self):
        self.source_name = "Base"

    def fetch_data(self):
        """Override this method in child classes"""
        return []
