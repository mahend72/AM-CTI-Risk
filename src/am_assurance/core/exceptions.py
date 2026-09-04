"""Exception hierarchy for am_assurance."""

from __future__ import annotations


class AMAssuranceError(Exception):
    """Base class for all am_assurance errors."""


class ConfigError(AMAssuranceError):
    """A configuration file is missing, malformed, or fails a sanity check."""


class STIXLoadError(AMAssuranceError):
    """The STIX bundle could not be loaded or is structurally invalid."""


class DataValidationError(AMAssuranceError):
    """Raised only for validation problems severe enough to abort a run.

    Most validation findings (see core/validation.py) are recorded as
    INFO/WARNING/ERROR entries in the validation report rather than raised
    - per the restructuring brief, invalid records are never silently
    dropped. This exception is reserved for structural problems that make
    it impossible to proceed at all (e.g. the bundle has no `objects` key).
    """
