"""Typed knowledge-layer failures."""

from __future__ import annotations


class KnowledgeError(Exception):
    """Base class for knowledge ingestion and retrieval failures."""


class KnowledgeAccessDenied(KnowledgeError):
    """A tenant boundary would be crossed."""


class KnowledgeIntegrityError(KnowledgeError):
    """A unit's declared content hash does not match its content."""


class KnowledgeConflict(KnowledgeError):
    """A unit identifier or supersession chain is inconsistent."""
