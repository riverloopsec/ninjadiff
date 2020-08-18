import binaryninja as binja

def compare_instructions(src_instr: binja.HighLevelILInstruction, dst_instr: binja.HighLevelILInstruction) -> bool:
  if src_instr.operation != dst_instr.operation:
    return False

  operation = src_instr.operation
  if operation == binja.HighLevelILOperation.HLIL_CALL:
    return compare_calls(src_instr, dst_instr)

  if operation == binja.HighLevelILOperation.HLIL_ASSIGN:
    src_var, src_val = src_instr.operands
    dst_var, dst_val = dst_instr.operands
    if (src_var.operation != dst_var.operation) or (src_val.operation != dst_val.operation):
      return False

    elif operation == binja.HighLevelILOperation.HLIL_CALL:
      return compare_calls(src_instr, dst_instr)

  elif operation == binja.HighLevelILOperation.HLIL_WHILE:
      src_condition = src_instr.operands[0]
      dst_condition = dst_instr.operands[0]
      print('src_condition: {}    dst_condition: {}'.format(src_condition, dst_condition))
      return src_condition == dst_condition

  # probably nothing address specific
  return src_instr == dst_instr

def compare_calls(src_instr: binja.HighLevelILInstruction, dst_instr: binja.HighLevelILInstruction) -> bool:
  print('src: {}'.format(src_instr))
  print('dst: {}'.format(dst_instr))
  src_function = src_instr.operands[0]
  dst_function = dst_instr.operands[0]
  # TODO: verify the function being called is the same

  src_args = src_instr.operands[1]
  dst_args = dst_instr.operands[1]
  if len(src_args) != len(dst_args):
    return False
  for i in range(len(src_args)):
    src_arg = src_args[i]
    dst_arg = dst_args[i]
    if src_arg.operation != dst_arg.operation:
      return False

    # ignore contant pointers, as their addresses will vary
    if src_arg.operation == binja.HighLevelILOperation.HLIL_CONST_PTR:
      continue

    return src_arg == dst_arg
