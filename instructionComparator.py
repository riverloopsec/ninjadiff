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

  # ignore branch targets, comparisions should only be based on the condition
  elif (operation == binja.HighLevelILOperation.HLIL_WHILE) or (operation == binja.HighLevelILOperation.HLIL_IF):
      src_condition = src_instr.operands[0]
      dst_condition = dst_instr.operands[0]

      if len(src_condition.operands) != len(dst_condition.operands):
        return False

      for i in range(len(src_condition.operands)):
        src_operand = src_condition.operands[i]
        dst_operand = dst_condition.operands[i]

        if (src_operand.operation == binja.HighLevelILOperation.HLIL_STRUCT_FIELD or
                src_operand.operation == binja.HighLevelILOperation.HLIL_VAR) and \
          (dst_operand.operation == binja.HighLevelILOperation.HLIL_STRUCT_FIELD or
           dst_operand.operation == binja.HighLevelILOperation.HLIL_VAR):
          continue
        if src_operand != dst_operand:
          return False
      return True

  # probably nothing address specific
  return src_instr == dst_instr

def compare_calls(src_instr: binja.HighLevelILInstruction, dst_instr: binja.HighLevelILInstruction) -> bool:
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

    # auto generated variable names may not match
    if (src_arg.operation == binja.HighLevelILOperation.HLIL_VAR) or \
            (src_arg.operation == binja.HighLevelILOperation.HLIL_STRUCT_FIELD):
      pass

    # ignore contant pointers, as their addresses will vary
    if src_arg.operation == binja.HighLevelILOperation.HLIL_CONST_PTR:
      # check if the pointer is a string, and if so compare string values between instructions
      src_bv = src_instr.il_basic_block.view
      dst_bv = dst_instr.il_basic_block.view
      src_string_at = src_bv.get_ascii_string_at(src_bv.start + src_arg.value.value)
      dst_string_at = dst_bv.get_ascii_string_at(dst_bv.start + dst_arg.value.value)
      print(src_string_at)
      print(dst_string_at)

      if (src_string_at is not None) and (dst_string_at is not None):
        return src_string_at.value == dst_string_at.value
      # ignore pointers which don't point to non primitive objects
      continue

    return src_arg == dst_arg
