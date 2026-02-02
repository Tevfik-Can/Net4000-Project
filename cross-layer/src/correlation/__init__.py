"""
Cross-Layer Correlation Module

This module provides tools for correlating kernel-level eBPF telemetry
with application-level metrics.
"""

from .correlator import CrossLayerCorrelator, CorrelatedEvent

__all__ = ['CrossLayerCorrelator', 'CorrelatedEvent']
