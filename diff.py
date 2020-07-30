#!/usr/bin/env python3

# Copyright 2019 River Loop Security LLC, All Rights Reserved
# Author Rylan O'Connell

import binaryninja as binja

import math
from typing import Tuple, List, Dict

from . import functionTypes

Binary_View = binja.binaryview.BinaryView


class BackgroundDiffer(binja.BackgroundTaskThread):
    def __init__(self, src_bv: Binary_View, dst_bv: Binary_View):
        binja.BackgroundTaskThread.__init__(self, 'Diffing...', True)
        self.src_bv = src_bv
        self.dst_bv = dst_bv

    def run(self):
        print('started diffing...')
        dst_mismatched_tt = self.dst_bv.create_tag_type('Difference', '🚫')
        src_mismatched_tt = self.src_bv.create_tag_type('Difference', '🚫')
        new_function_tt = self.src_bv.create_tag_type('New function', '➕')

        dst_functions = self.ingest(self.dst_bv)
        src_functions = self.ingest(self.src_bv)

        # align functions for diffing
        address_map = AddressMap()
        for src_function in src_functions:
            min_pairing, distance = self.get_min_pair(src_function, dst_functions)

            # if pairing failed (ie. no similar functions in the dest binary), assume it is not present in dest
            if min_pairing is None:
                tag = src_function.source_function.create_tag(new_function_tt, 'No matching functions')
                src_function.source_function.add_user_address_tag(src_function.address, tag)
                for bb in src_function.basic_blocks:
                    for instr in bb.source_block:
                        src_function.source_function.set_user_instr_highlight(
                            instr.address,
                            binja.highlight.HighlightStandardColor.RedHighlightColor
                        )
                continue

            # attempt to build a mapping between addresses in the source and destination binaries
            for src_bb in src_function.basic_blocks:
                try:
                    index = min_pairing.basic_blocks.index(src_bb)
                    dst_bb = min_pairing.basic_blocks[index]
                    address_map.add_mapping(src_addr=src_bb.address, dst_addr=dst_bb.address)

                # basic block not found in the dest binary
                except ValueError:
                    pass

    def get_min_pair(self, function: functionTypes.FunctionWrapper, pairings: List[functionTypes.FunctionWrapper]) -> Tuple[functionTypes.FunctionWrapper, float]:
        min_distance = math.inf
        min_pairing = None

        for pairing in pairings:
            distance = function.distance(pairing)
            # only accept pairings "close" to the original (accounting for function size)
            if (distance < min_distance) and \
                    (distance < 0.40 * (function.number_of_basic_blocks() + .1 * function.number_of_edges())):
                min_distance = distance
                min_pairing = pairing

        return min_pairing, min_distance

    def ingest(self, bv: Binary_View) -> List[functionTypes.FunctionWrapper]:
        functions = []
        # TODO: exclude thunks/etc.
        for function in bv.functions:
            # ignore small functions to minimize false positives
            if len(function.basic_blocks) < 5:
                continue

            function_with_metadata = functionTypes.FunctionWrapper(function)
            functions.append(function_with_metadata)

        return functions


class AddressMap:
    def __init__(self):
        self.src_to_dst = {}
        self.dst_to_src = {}

    def add_mapping(self, src_addr, dst_addr):
        self.src_to_dst[src_addr] = dst_addr
        self.dst_to_src[dst_addr] = src_addr

    def src2dst(self, src_addr):
        return self.src_to_dst[src_addr]

    def dst2src(self, dst_addr):
        return self.dst_to_src[dst_addr]
