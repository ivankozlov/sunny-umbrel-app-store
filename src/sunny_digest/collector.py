"""The model-only service. Telegram and delivery belong to guardian_engine."""
from .model_collector import serve

__all__ = ["serve"]
