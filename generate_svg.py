#!/usr/bin/env python3
"""
Parse a class relationship file and generate a large, well-spaced SVG
using Graphviz for layout.

Input file format:
  Child: Parent1, Parent2, ...   (all ancestors listed, script infers direct only)
  OR pass --mermaid to parse a classDiagram mermaid file instead.

Requirements:
  - graphviz system package (apt install graphviz / brew install graphviz)
  - graphviz python package: pip install graphviz

Usage:
  python3 generate_svg.py relationships.txt
  python3 generate_svg.py diagram.mmd --mermaid
  python3 generate_svg.py relationships.txt --output my_diagram.svg
  python3 generate_svg.py relationships.txt --direction TB   # TB or LR
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Color scheme — edit these to change node colors per prefix group
# ---------------------------------------------------------------------------
COLOR_GROUPS = [
    # (prefix, fill, border, text)
    ("ZT",        "#dbeafe", "#1e40af", "#1e3a8a"),   # blue
    ("BF",        "#dcfce7", "#166534", "#14532d"),   # green
    ("UI",        "#fef9c3", "#854d0e", "#713f12"),   # yellow
    ("IScroller", "#fef9c3", "#854d0e", "#713f12"),   # yellow (same as UI)
    ("IDirect",   "#fce7f3", "#9d174d", "#831843"),   # pink
    ("IDirectDraw","#fce7f3","#9d174d", "#831843"),   # pink
    ("IUnknown",  "#fce7f3", "#9d174d", "#831843"),   # pink
    ("DX",        "#ede9fe", "#5b21b6", "#4c1d95"),   # purple
    ("SND",       "#ede9fe", "#5b21b6", "#4c1d95"),   # purple
    ("GX",        "#ede9fe", "#5b21b6", "#4c1d95"),   # purple
    ("HGDIOBJ",   "#ede9fe", "#5b21b6", "#4c1d95"),   # purple
    ("HB",        "#ede9fe", "#5b21b6", "#4c1d95"),   # purple
    ("HF",        "#ede9fe", "#5b21b6", "#4c1d95"),   # purple
    ("HP",        "#ede9fe", "#5b21b6", "#4c1d95"),   # purple
]
COLOR_DEFAULT = ("#f1f5f9", "#475569", "#1e293b")     # gray


def node_color(name: str) -> tuple[str, str, str]:
    for prefix, fill, border, text in COLOR_GROUPS:
        if name.startswith(prefix):
            return fill, border, text
    return COLOR_DEFAULT


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_relationships(text: str) -> tuple[list[tuple[str, str]], set[str]]:
    """
    Parse 'Child: Parent1, Parent2, ...' format.
    Infers direct parents only (removes transitive ancestors).
    Returns (edges, all_nodes).
    """
    raw: dict[str, list[str]] = {}
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        child, _, parents_str = line.partition(":")
        child = child.strip()
        parents = [p.strip() for p in parents_str.split(",") if p.strip()]
        raw[child] = parents

    # Infer direct parents
    edges = []
    all_nodes: set[str] = set(raw.keys())
    for parents in raw.values():
        all_nodes.update(parents)

    for child, all_parents in raw.items():
        indirect = set()
        for candidate in all_parents:
            indirect |= set(raw.get(candidate, [])) & set(all_parents)
        for parent in all_parents:
            if parent not in indirect:
                edges.append((parent, child))

    return edges, all_nodes


def parse_mermaid(text: str) -> tuple[list[tuple[str, str]], set[str]]:
    """
    Parse a Mermaid classDiagram source.
    Returns (edges, all_nodes).
    """
    edges = []
    all_nodes: set[str] = set()

    for line in text.strip().splitlines():
        line = line.strip()
        m = re.match(r'(\w+)\s*<\|--\s*(\w+)', line)
        if m:
            parent, child = m.group(1), m.group(2)
            edges.append((parent, child))
            all_nodes.update([parent, child])
        m2 = re.match(r'class\s+(\w+)\s*$', line)
        if m2:
            all_nodes.add(m2.group(1))

    return edges, all_nodes


# ---------------------------------------------------------------------------
# DOT generation & rendering
# ---------------------------------------------------------------------------

def build_dot(
    edges: list[tuple[str, str]],
    all_nodes: set[str],
    direction: str = "LR",
    ranksep: float = 1.8,
    nodesep: float = 0.5,
) -> str:
    lines = [
        "digraph G {",
        f'  graph [rankdir={direction}, ranksep={ranksep}, nodesep={nodesep}, '
        f'splines=ortho, fontname="Arial", bgcolor="white"];',
        '  node [shape=box, style="filled,rounded", fontname="Arial", '
        f'fontsize=13, height=0.5, margin="0.25,0.15"];',
        '  edge [dir=back, arrowhead=onormal, arrowsize=1.0, '
        f'penwidth=1.2, color="#94a3b8"];',
    ]

    for node in sorted(all_nodes):
        fill, border, txt = node_color(node)
        lines.append(
            f'  "{node}" [fillcolor="{fill}", color="{border}", fontcolor="{txt}"];'
        )

    for parent, child in edges:
        lines.append(f'  "{parent}" -> "{child}";')

    lines.append("}")
    return "\n".join(lines)


def render_svg(dot_source: str, output_path: Path) -> None:
    """Run graphviz dot to produce SVG, then fix pt → px units."""
    result = subprocess.run(
        ["dot", "-Tsvg"],
        input=dot_source,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("Graphviz error:", result.stderr, file=sys.stderr)
        sys.exit(1)

    svg = result.stdout

    # Convert pt dimensions to px (1pt ≈ 1.333px)
    m = re.search(r'width="([\d.]+)pt".*?height="([\d.]+)pt"', svg)
    if m:
        w_px = int(float(m.group(1)) * 1.333)
        h_px = int(float(m.group(2)) * 1.333)
        svg = re.sub(r'width="[\d.]+pt"', f'width="{w_px}"', svg)
        svg = re.sub(r'height="[\d.]+pt"', f'height="{h_px}"', svg)
        print(f"Output dimensions: {w_px} x {h_px} px")

    output_path.write_text(svg)
    print(f"SVG written to: {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a large SVG class hierarchy diagram."
    )
    parser.add_argument("input", help="Input file path")
    parser.add_argument(
        "--mermaid", action="store_true",
        help="Parse as Mermaid classDiagram instead of relationship format"
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Output SVG path (default: <input>.svg)"
    )
    parser.add_argument(
        "--direction", "-d", choices=["LR", "TB"], default="LR",
        help="Graph direction: LR (left-right) or TB (top-bottom). Default: LR"
    )
    parser.add_argument(
        "--ranksep", type=float, default=1.8,
        help="Spacing between ranks (default: 1.8)"
    )
    parser.add_argument(
        "--nodesep", type=float, default=0.5,
        help="Spacing between nodes in same rank (default: 0.5)"
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    text = input_path.read_text()

    if args.mermaid:
        edges, all_nodes = parse_mermaid(text)
    else:
        edges, all_nodes = parse_relationships(text)

    print(f"Parsed {len(all_nodes)} nodes, {len(edges)} edges")

    dot_source = build_dot(
        edges, all_nodes,
        direction=args.direction,
        ranksep=args.ranksep,
        nodesep=args.nodesep,
    )

    output_path = Path(args.output) if args.output else input_path.with_suffix(".svg")
    render_svg(dot_source, output_path)


if __name__ == "__main__":
    main()
