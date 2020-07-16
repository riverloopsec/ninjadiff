#!/usr/bin/env python3

# Copyright 2019 River Loop Security LLC, All Rights Reserved
# Author Rylan O'Connell

import binaryninja as binja

import argparse
import os
import sys
import math
from typing import Tuple, List, Dict

from . import hashashin

Binary_View = binja.binaryview.BinaryView


class BackgroundDiffer(binja.plugin.BackgroundTask):
    def __init__(self, src_bv: Binary_View, dst_bv: Binary_View):
        binja.plugin.BackgroundTaskThread.__init__(self, 'Diffing...', True)
        self.src_bv = src_bv
        self.dst_bv = dst_bv

    def run(self):
        print('started diffing...')
        functions = []
        # TODO: exclude thunks/etc.
        for function in self.src_bv.functions:
            # ignore small functions to minimize false positives
            if len(function.basic_blocks) < 5:
                continue

            hash_cfg = self.function_graph(self.src_bv, function.hlil)
            functions.append(hash_cfg)

        mismatched_tt = self.dst_bv.create_tag_type('Difference', '🚫')
        new_function_tt = self.dst_bv.create_tag_type('New function', '➕')

        # align functions for diffing
        # TODO: exclude thunks/etc.
        for function in self.dst_bv.functions:
            # ignore small functions to avoid false positives
            if len(function.basic_blocks) < 5:
                continue

            hash_cfg = self.function_graph(self.dst_bv, function.hlil)
            min_pairing, distance = self.get_min_pair(hash_cfg, functions)

            # if pairing failed, the function must be new to this binary
            if min_pairing is None:
                print('No suitable function pairing for {}'.format(function.name))
                tag = function.create_tag(new_function_tt, 'New function')
                function.add_user_address_tag(function.start, tag)

                for bb in function.hlil:
                    for instr in bb:
                        function.set_user_instr_highlight(
                            instr.address,
                            binja.highlight.HighlightStandardColor.RedHighlightColor
                        )
                continue

            if distance > 0:
                print('Successfully aligned {} to {} (delta: {})'.format(function.name, min_pairing.name, distance))

            for bb in function.hlil.basic_blocks:
                # TODO: optmize to avoid second hashing
                bb_hash = hashashin.brittle_hash(self.dst_bv, bb)

                # basic block matches a block in the source
                if min_pairing.has_node(bb_hash):
                    for instr in bb:
                        function.set_user_instr_highlight(
                            instr.address,
                            binja.highlight.HighlightStandardColor.GreenHighlightColor
                        )

                # basic block differs, but function is similar
                else:
                    print('tagging mismatch at {}...'.format(hex(bb.start + function.start)))
                    tag = function.create_tag(mismatched_tt, '')
                    function.add_user_address_tag(bb.start + function.start, tag)
                    for instr in bb:
                        function.set_user_instr_highlight(
                            instr.address,
                            binja.highlight.HighlightStandardColor.RedHighlightColor
                        )

    def get_min_pair(self, function, pairings):
        min_distance = math.inf
        min_pairing = None

        for pairing in pairings:
            distance = self.function_difference(function, pairing)
            # only accept pairings "close" to the original (accounting for function size)
            if (distance < min_distance) and \
                    (distance < 0.40 * (function.number_of_nodes() + .1 * function.number_of_edges())):
                min_distance = distance
                min_pairing = pairing

        return min_pairing, min_distance


    def function_difference(self, f1, f2) -> float:
        distance = 0.0

        for block in f1.nodes:
            if not f2.has_node(block):
                distance += 1
        for block in f2.nodes:
            if not f1.has_node(block):
                distance += 1

        for edge in f1.edges:
            if not f2.has_edge(edge[0], edge[1]):
                distance += 0.1
        for edge in f2.edges:
            if not f1.has_edge(edge[0], edge[1]):
                distance += 0.1

        return distance


    def function_graph(self, bv: binja.binaryview.BinaryView, function: binja.highlevelil.HighLevelILFunction):
        graph = Graph()
        graph.name = function.source_function.name

        bbs = {}
        for bb in function:
            bb_hash = hashashin.brittle_hash(bv, bb)
            graph.add_node(bb_hash)
            bbs[bb] = bb_hash

        for bb in function:
            bb_hash = bbs[bb]
            outgoing = bb.outgoing_edges
            for edge in outgoing:
                target_hash = bbs[edge.target]
                graph.add_edge(bb_hash, target_hash)

        return graph


# minimal graph class to avoid dependency on networkx
class Graph:
    def __init__(self):
        self.nodes = []
        self.edges = {}
        self.name = ''

    def add_node(self, node):
        self.nodes.append(node)

    def add_edge(self, u, v):
        if u in self.edges.keys():
            self.edges[u].append(v)
        else:
            self.edges[u] = [v]

    def has_node(self, node):
        return node in self.nodes

    def has_edge(self, u, v):
        if u in self.edges.keys():
            for child in self.edges[u]:
                if child == v:
                    return True
        return False

    def number_of_nodes(self):
        return len(self.nodes)

    def number_of_edges(self):
        return len(self.edges.values())
