"""
Adversarial Bootkit Generator

Generates mutated bootkit variants to stress-test the scanner's detection
capability. Implements multiple mutation strategies including trampoline
obfuscation, encryption wrappers, and polymorphic stub generation.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from .mutator import BootkitMutator, MutationStrategy
from .templates import BootkitTemplate, TemplateLibrary
from .generator import AdversarialGenerator
from .evaluator import DetectionEvaluator

__all__ = [
    'BootkitMutator',
    'MutationStrategy',
    'BootkitTemplate',
    'TemplateLibrary',
    'AdversarialGenerator',
    'DetectionEvaluator',
]
