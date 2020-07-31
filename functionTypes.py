#!/usr/bin/env python3

# Copyright 2020 River Loop Security LLC, All Rights Reserved
# Author Rylan O'Connell

from binaryninja import HighLevelILBasicBlock
from binaryninja import HighLevelILInstruction
from binaryninja import Function

from typing import List, Dict

from . import hashashin

class BasicBlockWrapper:
    def __init__(self, bb: HighLevelILBasicBlock, bb_hash: str):
        self.address: int = bb.start + bb.function.start
        self.instructions: List[HighLevelILInstruction] = [instr for instr in bb]
        self.hash: str = bb_hash
        self.source_block: HighLevelILBasicBlock = bb  # TODO: inherit/initialize values from HighLevelILBasicBlock

    def __eq__(self, other):
        if type(self) == type(other):
            return self.hash == other.hash
        return False

    def __hash__(self):
        return int(self.hash, 16)


# minimal graph class to avoid dependency on networkx
class FunctionWrapper:
    def __init__(self, function: Function):
        self.basic_blocks: List[BasicBlockWrapper] = []
        self.edges: Dict[BasicBlockWrapper, List[BasicBlockWrapper]] = {}
        self.address: int = function.start
        self.source_function: Function = function  # TODO:  inherit/initialize properties from Function

        # create BasicBlock objects to represent all blocks in the function
        for bb in function.hlil.basic_blocks:
            self.add_basic_block(bb)

    def add_basic_block(self, bb: HighLevelILBasicBlock):
        bb_hash = hashashin.brittle_hash(self.source_function.view, bb)
        node = BasicBlockWrapper(bb, bb_hash)

        # ensure we don't add a basic block if we've already "discovered" it
        if node in self.basic_blocks:
            return

        self.basic_blocks.append(node)

        for edge in bb.outgoing_edges:
            target_block = edge.target
            target_hash = hashashin.brittle_hash(self.source_function.view, target_block)
            target_node = BasicBlockWrapper(target_block, target_hash)

            # recursively discover child nodes
            if target_node not in self.basic_blocks:
                self.add_basic_block(target_block)

            self.add_edge(node, target_node)

    def add_edge(self, u: BasicBlockWrapper, v: BasicBlockWrapper):
        if u in self.edges.keys():
            self.edges[u].append(v)
        else:
            self.edges[u] = [v]

    def has_node(self, node: BasicBlockWrapper):
        return node in self.basic_blocks

    def has_edge(self, u: BasicBlockWrapper, v: BasicBlockWrapper):
        if u in self.edges.keys():
            for child in self.edges[u]:
                if child == v:
                    return True
        return False

    def number_of_basic_blocks(self):
        return len(self.basic_blocks)

    def number_of_edges(self):
        return len(self.edges.values())

    # TODO: experiment with similarity metrics
    def distance(self, other) -> float:
        distance = 0.0

        for block in self.basic_blocks:
            if not other.has_node(block):
                distance += 1
        for block in other.basic_blocks:
            if not self.has_node(block):
                distance += 1

        for k in self.edges.keys():
            for v in self.edges[k]:
                if not other.has_edge(k, v):
                    distance += 0.1
        for k in other.edges.keys():
            for v in other.edges[k]:
                if not self.has_edge(k, v):
                    distance += 0.1

        return distance
