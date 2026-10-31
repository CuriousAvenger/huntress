"""Versioned knowledge corpus with metadata + lexical hybrid retrieval."""

from .errors import (
    KnowledgeAccessDenied,
    KnowledgeConflict,
    KnowledgeError,
    KnowledgeIntegrityError,
)
from .hashing import knowledge_content_hash, make_knowledge_unit
from .seeds import SEED_TIME, SEED_UNITS, seed_units
from .service import GLOBAL_TENANT, KnowledgeService, KnowledgeStore

__version__ = "0.1.0"

__all__ = [
    "GLOBAL_TENANT",
    "SEED_TIME",
    "SEED_UNITS",
    "KnowledgeAccessDenied",
    "KnowledgeConflict",
    "KnowledgeError",
    "KnowledgeIntegrityError",
    "KnowledgeService",
    "KnowledgeStore",
    "knowledge_content_hash",
    "make_knowledge_unit",
    "seed_units",
]
