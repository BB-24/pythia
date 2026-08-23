class ScannerBaseException(Exception):
    """Base exception for expected scanner failures."""


class RegistryAuthError(ScannerBaseException):
    """Raised when registry authentication fails."""


class ImageNotFoundError(ScannerBaseException):
    """Raised when an image or requested manifest cannot be found."""


class ExtractionError(ScannerBaseException):
    """Raised when an image layer or archive cannot be extracted safely."""


class ParserError(ScannerBaseException):
    """Raised when a package metadata file cannot be parsed."""


class UpstreamAPIError(ScannerBaseException):
    """Raised when an upstream vulnerability service cannot be queried."""


class DatabaseError(ScannerBaseException):
    """Raised when the local vulnerability cache cannot be accessed."""


class ReportGenerationError(ScannerBaseException):
    """Raised when a report cannot be rendered or written."""
