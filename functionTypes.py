from binaryninja import HighLevelILBasicBlock
from binaryninja import Function
from binaryninja import BinaryView

from . import hashashin

class BasicBlock:
    def __init__(self, bb: HighLevelILBasicBlock, bb_hash: str):
        self.address = bb.start + bb.function.start
        self.instructions = bb.disassembly_text
        self.hash = bb_hash

    def __eq__(self, other):
        if type(self) == type(other):
            return self.hash == other.hash
        return False

# minimal graph class to avoid dependency on networkx
class Function:
    def __init__(self, function: Function):
        self.basic_blocks = []
        self.edges = {}
        self.name = function.name
        self.view = function.view

        # create BasicBlock objects to represent all blocks in the function
        for bb in function.hlil.basic_blocks:
            self.add_basic_block(bb)

    def add_basic_block(self, bb: HighLevelILBasicBlock):
        bb_hash = hashashin.brittle_hash(self.view, bb)
        node = BasicBlock(bb, bb_hash)

        # ensure we don't add a basic block if we've already "discovered" it
        if node in self.basic_blocks:
            return

        self.basic_blocks.append(node)

        for edge in bb.outgoing_edges:
            target_block = edge.target
            target_node = BasicBlock(target_block)

            # recursively discover child nodes
            if target_node not in self.basic_blocks:
                self.add_basic_block(target_block)

            self.add_edge(node, target_node)

    def add_edge(self, u: BasicBlock, v: BasicBlock):
        if u in self.edges.keys():
            self.edges[u].append(v)
        else:
            self.edges[u] = [v]

    def has_node(self, node: BasicBlock):
        return node in self.basic_blocks

    def has_edge(self, u: BasicBlock, v: BasicBlock):
        if u in self.edges.keys():
            for child in self.edges[u]:
                if child == v:
                    return True
        return False

    def number_of_basic_blocks(self):
        return len(self.basic_blocks)

    def number_of_edges(self):
        return len(self.edges.values())




