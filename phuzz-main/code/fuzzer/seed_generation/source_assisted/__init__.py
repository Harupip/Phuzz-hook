"""Source-assisted seed generation and plugin-source handling."""

from .input_extractor import InputSignatureExtractor
from .source_materializer import materialize_plugin_source
from .source_resolver import SourcePathResolver, SourceResolution
from .static_generator import StaticSeedGenerator

__all__ = [
    "InputSignatureExtractor",
    "SourcePathResolver",
    "SourceResolution",
    "StaticSeedGenerator",
    "materialize_plugin_source",
]
