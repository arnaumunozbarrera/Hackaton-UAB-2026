"""investigation: attack-chain reconstruction (N2) for escalated alerts.

python -m src.investigation ALR-... [--mock | --claude-code]
"""

from .catalogue import InvestigationBackend
from .runner import ChainResult, ChainRunner
from .service import ChainService

__all__ = ["ChainResult", "ChainRunner", "ChainService", "InvestigationBackend"]
