"""
Attestation Graph - Directed provenance graph for firmware components.

Builds a directed graph: firmware.rom → FV[guid] → FFS[guid] → signed_by[key] → issued_by[CA]

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class NodeType(Enum):
    FIRMWARE_IMAGE = "firmware_image"
    FIRMWARE_VOLUME = "firmware_volume"
    FIRMWARE_FILE = "firmware_file"
    PE_IMAGE = "pe_image"
    SIGNING_KEY = "signing_key"
    CERTIFICATE_AUTHORITY = "certificate_authority"
    VENDOR = "vendor"


class RelationType(Enum):
    CONTAINS = "contains"
    SIGNED_BY = "signed_by"
    ISSUED_BY = "issued_by"
    PRODUCED_BY = "produced_by"
    DEPENDS_ON = "depends_on"


@dataclass
class ComponentNode:
    """A node in the attestation graph representing a firmware component."""
    node_id: str
    node_type: NodeType
    name: str
    guid: Optional[str] = None
    hash_sha256: Optional[str] = None
    size: int = 0
    metadata: Dict = field(default_factory=dict)

    def __hash__(self):
        return hash(self.node_id)

    def __eq__(self, other):
        if not isinstance(other, ComponentNode):
            return NotImplemented
        return self.node_id == other.node_id


@dataclass
class RelationshipEdge:
    """A directed edge in the attestation graph."""
    source_id: str
    target_id: str
    relation_type: RelationType
    metadata: Dict = field(default_factory=dict)


class AttestationGraph:
    """
    Directed provenance graph mapping firmware components to their origin.

    Structure:
      firmware.rom → FV[guid] → FFS[guid] → signed_by[key] → issued_by[CA]
                                           → produced_by[vendor]
    """

    def __init__(self):
        self.nodes: Dict[str, ComponentNode] = {}
        self.edges: List[RelationshipEdge] = []
        self._adjacency: Dict[str, List[RelationshipEdge]] = {}

    def add_node(self, node: ComponentNode) -> None:
        self.nodes[node.node_id] = node
        if node.node_id not in self._adjacency:
            self._adjacency[node.node_id] = []

    def add_edge(self, edge: RelationshipEdge) -> None:
        self.edges.append(edge)
        if edge.source_id not in self._adjacency:
            self._adjacency[edge.source_id] = []
        self._adjacency[edge.source_id].append(edge)

    def get_node(self, node_id: str) -> Optional[ComponentNode]:
        return self.nodes.get(node_id)

    def get_edges_from(self, node_id: str) -> List[RelationshipEdge]:
        return self._adjacency.get(node_id, [])

    def get_edges_to(self, node_id: str) -> List[RelationshipEdge]:
        return [e for e in self.edges if e.target_id == node_id]

    def get_children(self, node_id: str) -> List[ComponentNode]:
        edges = self.get_edges_from(node_id)
        return [self.nodes[e.target_id] for e in edges if e.target_id in self.nodes]

    def get_parents(self, node_id: str) -> List[ComponentNode]:
        edges = self.get_edges_to(node_id)
        return [self.nodes[e.source_id] for e in edges if e.source_id in self.nodes]

    def get_signing_chain(self, node_id: str) -> List[ComponentNode]:
        """Walk the signing chain from a component up to the root CA."""
        chain = []
        current = node_id
        visited: Set[str] = set()

        while current and current not in visited:
            visited.add(current)
            edges = self.get_edges_from(current)
            signing_edges = [
                e for e in edges
                if e.relation_type in (RelationType.SIGNED_BY, RelationType.ISSUED_BY)
            ]
            if not signing_edges:
                break
            next_id = signing_edges[0].target_id
            if next_id in self.nodes:
                chain.append(self.nodes[next_id])
            current = next_id

        return chain

    def get_unsigned_components(self) -> List[ComponentNode]:
        """Find all FFS/PE components with no signing relationship."""
        unsigned = []
        for node in self.nodes.values():
            if node.node_type in (NodeType.FIRMWARE_FILE, NodeType.PE_IMAGE):
                edges = self.get_edges_from(node.node_id)
                has_signing = any(
                    e.relation_type == RelationType.SIGNED_BY for e in edges
                )
                if not has_signing:
                    unsigned.append(node)
        return unsigned

    def get_unknown_vendors(self) -> List[ComponentNode]:
        """Find components with no known vendor association."""
        unknown = []
        for node in self.nodes.values():
            if node.node_type == NodeType.FIRMWARE_FILE:
                edges = self.get_edges_from(node.node_id)
                has_vendor = any(
                    e.relation_type == RelationType.PRODUCED_BY for e in edges
                )
                if not has_vendor:
                    unknown.append(node)
        return unknown

    @property
    def component_count(self) -> int:
        return len([
            n for n in self.nodes.values()
            if n.node_type in (NodeType.FIRMWARE_FILE, NodeType.PE_IMAGE)
        ])

    def to_dict(self) -> Dict:
        """Serialize graph to dictionary for JSON output."""
        return {
            'nodes': [
                {
                    'id': n.node_id,
                    'type': n.node_type.value,
                    'name': n.name,
                    'guid': n.guid,
                    'hash': n.hash_sha256,
                    'size': n.size,
                    'metadata': n.metadata,
                }
                for n in self.nodes.values()
            ],
            'edges': [
                {
                    'source': e.source_id,
                    'target': e.target_id,
                    'relation': e.relation_type.value,
                    'metadata': e.metadata,
                }
                for e in self.edges
            ],
        }

    def to_dot(self) -> str:
        """Generate DOT/Graphviz representation of the attestation graph."""
        lines = ['digraph attestation {', '  rankdir=LR;']

        type_colors = {
            NodeType.FIRMWARE_IMAGE: '#2196F3',
            NodeType.FIRMWARE_VOLUME: '#4CAF50',
            NodeType.FIRMWARE_FILE: '#FF9800',
            NodeType.PE_IMAGE: '#F44336',
            NodeType.SIGNING_KEY: '#9C27B0',
            NodeType.CERTIFICATE_AUTHORITY: '#795548',
            NodeType.VENDOR: '#607D8B',
        }

        for node in self.nodes.values():
            color = type_colors.get(node.node_type, '#000000')
            label = f"{node.name}\\n{node.node_type.value}"
            lines.append(
                f'  "{node.node_id}" [label="{label}", '
                f'style=filled, fillcolor="{color}40", color="{color}"];'
            )

        relation_styles = {
            RelationType.CONTAINS: 'solid',
            RelationType.SIGNED_BY: 'bold',
            RelationType.ISSUED_BY: 'dashed',
            RelationType.PRODUCED_BY: 'dotted',
            RelationType.DEPENDS_ON: 'tapered',
        }

        for edge in self.edges:
            style = relation_styles.get(edge.relation_type, 'solid')
            lines.append(
                f'  "{edge.source_id}" -> "{edge.target_id}" '
                f'[label="{edge.relation_type.value}", style={style}];'
            )

        lines.append('}')
        return '\n'.join(lines)

    def to_mermaid(self) -> str:
        """Generate Mermaid diagram representation."""
        lines = ['graph LR']

        for node in self.nodes.values():
            shape_map = {
                NodeType.FIRMWARE_IMAGE: ('([', '])'),
                NodeType.FIRMWARE_VOLUME: ('{{', '}}'),
                NodeType.FIRMWARE_FILE: ('[', ']'),
                NodeType.PE_IMAGE: ('((', '))'),
                NodeType.SIGNING_KEY: ('[/', '/]'),
                NodeType.CERTIFICATE_AUTHORITY: (['[', ']']),
                NodeType.VENDOR: ('>', ']'),
            }
            left, right = shape_map.get(node.node_type, ('[', ']'))
            safe_id = node.node_id.replace('-', '_').replace('.', '_')
            lines.append(f'  {safe_id}{left}"{node.name}"{right}')

        for edge in self.edges:
            src = edge.source_id.replace('-', '_').replace('.', '_')
            tgt = edge.target_id.replace('-', '_').replace('.', '_')
            lines.append(f'  {src} -->|{edge.relation_type.value}| {tgt}')

        return '\n'.join(lines)
