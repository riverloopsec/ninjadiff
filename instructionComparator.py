import binaryninja as binja


def compare_instructions(src_instr: binja.HighLevelILInstruction, dst_instr: binja.HighLevelILInstruction) -> bool:
  if src_instr.operation != dst_instr.operation:
    return False

  operation = src_instr.operation
  if operation == binja.HighLevelILOperation.HLIL_CALL:
    return compare_calls(src_instr, dst_instr)

  if (operation == binja.HighLevelILOperation.HLIL_ASSIGN) or (operation == binja.HighLevelILOperation.HLIL_VAR_INIT):
    src_var, src_val = src_instr.operands
    dst_var, dst_val = dst_instr.operands

    # left hand side of assignment operation can be variable, field, etc.
    if type(src_var) == type(dst_var):
      if type(src_var) == binja.Variable:
        if src_var.type != dst_var.type:
          return False
      elif type(src_var) == binja.highlevelil.HighLevelILInstruction:
        if src_var.operation != dst_var.operation:
          return False
    else:
      return False

    if src_val.operation != dst_val.operation:
      return False

    elif operation == binja.HighLevelILOperation.HLIL_CALL:
      return compare_calls(src_instr, dst_instr)

    # TODO: check other arithemetic operations (ie. DIV, MOD, etc.)
    if (operation == binja.HighLevelILOperation.HLIL_ADD) or \
            (operation == binja.HighLevelILOperation.HLIL_SUB) or \
            (operation == binja.HighLevelILOperation.HLIL_MUL):
      return compare_arithmetic(src_instr, dst_instr)

  # ignore branch targets, comparisions should only be based on the condition
  elif (operation == binja.HighLevelILOperation.HLIL_WHILE) or (operation == binja.HighLevelILOperation.HLIL_IF):
    src_condition = src_instr.operands[0]
    dst_condition = dst_instr.operands[0]

    if len(src_condition.operands) != len(dst_condition.operands):
      return False

    for i in range(len(src_condition.operands)):
      src_operand = src_condition.operands[i]
      dst_operand = dst_condition.operands[i]
      if (type(src_operand) != binja.HighLevelILInstruction) or (type(dst_operand) != binja.HighLevelILInstruction):
        continue
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


def compare_derefs(src_instr: binja.HighLevelILInstruction, dst_instr: binja.HighLevelILInstruction) -> bool:
  src_pointer = src_instr.src
  dst_pointer = dst_instr.src
  if src_pointer.operation != dst_pointer.operation:
    return False

  operation = src_pointer.operation
  # TODO: extract strings/constants
  if operation == binja.HighLevelILOperation.HLIL_CONST_PTR:
    pass
  elif operation == binja.HighLevelILOperation.HLIL_VAR:
    return src_pointer.var.type == dst_pointer.var.type
  elif (operation == binja.HighLevelILOperation.HLIL_ADD) or \
    (operation == binja.HighLevelILOperation.HLIL_SUB) or \
    (operation == binja.HighLevelILOperation.HLIL_MUL):
    return compare_arithmetic(src_pointer, dst_pointer)

  else:
    print('[!] unexpected pointer type {} at {}'.format(operation, hex(src_instr.address)))
    return False

def compare_arithmetic(src_instr: binja.HighLevelILInstruction, dst_instr: binja.HighLevelILInstruction) -> bool:
  print(src_instr)
  print(dst_instr)
  num1_src, num2_src = src_instr.operands
  num1_dst, num2_dst = dst_instr.operands

  if (num1_src.operation != num2_src.operation) or (num1_dst.operation != num2_dst.operation):
    return False

  # TODO: check for floats as well
  # extract numeric constants
  if num1_src.operation == binja.HighLevelILOperation.HLIL_CONST:
    val1 = num1_src.constant
    val2 = num2_src.constant
    if val1 != val2:
      return False
  if num1_dst.operation == binja.HighLevelILOperation.HLIL_CONST:
    val1 = num1_dst.constant
    val2 = num2_dst.constant
    if val1 != val2:
      return False

  # compare variable refrences
  if num1_src.operation == binja.HighLevelILOperation.HLIL_CONST_PTR:
    return compare_derefs(src_instr, dst_instr)
  if num1_dst.operation == binja.HighLevelILOperation.HLIL_CONST_PTR:
    return compare_derefs(src_instr, dst_instr)

  return True


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
    if (type(src_arg) == binja.HighLevelILInstruction) and (type(dst_arg) == binja.HighLevelILInstruction):
      if src_arg.operation != dst_arg.operation:
       return False

      # ignore contant pointers, as their addresses will vary
      if src_arg.operation == binja.HighLevelILOperation.HLIL_CONST_PTR:
        # check if the pointer is a string, and if so compare string values between instructions
        src_bv = src_instr.il_basic_block.view
        dst_bv = dst_instr.il_basic_block.view
        src_string_at = src_bv.get_ascii_string_at(src_bv.start + src_arg.value.value)
        dst_string_at = dst_bv.get_ascii_string_at(dst_bv.start + dst_arg.value.value)
        if (src_string_at is not None) and (dst_string_at is not None):
          if src_string_at.value != dst_string_at.value:
            return False

      elif src_arg.operation == binja.HighLevelILOperation.HLIL_CONST:
          if src_arg.value != dst_arg.value:
            return False

    elif (type(src_arg) == binja.Variable) and (type(dst_arg) == binja.Variable):
       if src_arg.type != dst_arg.type:
        return False

  return True