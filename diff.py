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
from . import functionTypes

Binary_View = binja.binaryview.BinaryView


class BackgroundDiffer(binja.BackgroundTaskThread):
    def __init__(self, src_bv: Binary_View, dst_bv: Binary_View):
        binja.BackgroundTaskThread.__init__(self, 'Diffing...', True)
        self.src_bv = src_bv
        self.dst_bv = dst_bv

    def run(self):
        print('started diffing...')
        functions = {}
        # TODO: exclude thunks/etc.
        for function in self.dst_bv.functions:
            # ignore small functions to minimize false positives
            if len(function.basic_blocks) < 5:
                continue

            hash_cfg = self.function_graph(self.dst_bv, function.hlil)
            functions[hash_cfg] = function

        dst_mismatched_tt = self.dst_bv.create_tag_type('Difference', '🚫')
        src_mismatched_tt = self.src_bv.create_tag_type('Difference', '🚫')
        new_function_tt = self.src_bv.create_tag_type('New function', '➕')

        # align functions for diffing
        # TODO: exclude thunks/etc.
        for function in self.src_bv.functions:
            # ignore small functions to avoid false positives
            if len(function.basic_blocks) < 5:
                continue

            hash_cfg = self.function_graph(self.src_bv, function.hlil)
            min_pairing, distance = self.get_min_pair(hash_cfg, functions)

            # if pairing failed, the function must be new to this binary
            if min_pairing is None:
                print('No suitable function pairing for {}'.format(function.name))
                tag = function.create_tag(new_function_tt, 'New function')
                function.add_user_address_tag(function.start, tag)

                for bb in function.hlil_if_available:
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
                    # TODO: iterate through hlil instructions in functions[min_pairing] to diff at the instruction level
                    for instr in bb:
                        function.set_user_instr_highlight(
                            instr.address,
                            binja.highlight.HighlightStandardColor.GreenHighlightColor
                        )

                    # TODO: store bb info instead of having to recompute
                    dst_func = functions[min_pairing]
                    for dst_bb in dst_func.hlil_if_available.basic_blocks:
                        if bb_hash == hashashin.brittle_hash(self.dst_bv, dst_bb):
                            for instr in dst_bb:
                                dst_func.set_user_instr_highlight(
                                    instr.address,
                                    binja.highlight.HighlightStandardColor.GreenHighlightColor
                                )

                # basic block differs, but function is similar
                else:
                    print('tagging mismatch at {}...'.format(hex(bb.start + function.start)))
                    tag = function.create_tag(dst_mismatched_tt, '')
                    function.add_user_address_tag(bb.start + function.start, tag)
                    for instr in bb:
                        function.set_user_instr_highlight(
                            instr.address,
                            binja.highlight.HighlightStandardColor.RedHighlightColor
                        )
                    # TODO: figure out this logic
                    '''
                    dst_func = functions[min_pairing]
                    for dst_bb in dst_func.basic_blocks:
                        if bb_hash == hashashin.brittle_hash(self.dst_bv, dst_bb):
                            for instr in dst_bb:
                                dst_func.set_user_instr_highlight(
                                    instr.address,
                                    binja.highlight.HighlightStandardColor.GreenHighlightColor
                                )
                    '''

    def get_min_pair(self, function, pairings) -> Tuple[binja.function.Function, float]:
        min_distance = math.inf
        min_pairing = None

        for pairing in pairings.keys():
            distance = self.function_difference(function, pairing)
            # only accept pairings "close" to the original (accounting for function size)
            if (distance < min_distance) and \
                    (distance < 0.40 * (function.number_of_nodes() + .1 * function.number_of_edges())):
                min_distance = distance
                min_pairing = pairing

        return min_pairing, min_distance

    def function_difference(self, f1, f2) -> float:
        distance = 0.0

        for block in f1.basic_blocks:
            if not f2.has_node(block):
                distance += 1
        for block in f2.basic_blocks:
            if not f1.has_node(block):
                distance += 1

        for edge in f1.edges:
            if not f2.has_edge(edge[0], edge[1]):
                distance += 0.1
        for edge in f2.edges:
            if not f1.has_edge(edge[0], edge[1]):
                distance += 0.1

        return distance
