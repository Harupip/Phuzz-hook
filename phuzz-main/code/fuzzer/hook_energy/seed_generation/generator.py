"""Compatibility import for the static seed generator.

New code should import ``StaticSeedGenerator`` explicitly. Zend runtime
generation lives under ``seed_generation.zend_runtime``.
"""

from seed_generation.source_assisted.static_generator import StaticSeedGenerator

LiveHookSeedGenerator = StaticSeedGenerator

__all__ = ["LiveHookSeedGenerator", "StaticSeedGenerator"]
