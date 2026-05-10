# -*- coding: utf-8 -*-

#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython
# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
# PatchExtswAfterLwz.py
#
# Patches extsw rA,rA into NOP when rA is subsequently used as a base register
# in a memory access (lwz, stw, lbz, stb, ld, std, lhz, sth, lfd, stfd, ...),
# meaning the sign-extension is just the compiler widening a 32-bit pointer
# arithmetic result to 64-bit for the EA calculation.
#
# Leaves "PATCHED extsw->NOP ... | ORIG: XXXXXXXX" comment for reversibility.

import struct
import re
from ghidra.program.model.listing import CodeUnit
from ghidra.app.cmd.disassemble import DisassembleCommand

ORI_NOP      = 0x60000000
SCAN_FORWARD = 48    # how many instructions ahead to look for a memory use
DEBUG        = True

# PPC load/store mnemonics that use a base register (rB in disp(rB) form)
MEMORY_OPS = frozenset([
    "lwz","lwzu","lbz","lbzu","lhz","lhzu","lha","lhau",
    "lfs","lfd","lmw",
    "stw","stwu","stb","stbu","sth","sthu","stfs","stfd","stmw",
    "ld","ldu","lwa","std","stdu",
    "lwzx","lbzx","lhzx","lhax","lfsx","lfdx","stwx","stbx","sthx",
    "ldx","stdx","lwarx","stwcx.","ldarx","stdcx.",
])

def reg_name(insn, op_idx):
    if op_idx < insn.getNumOperands():
        return insn.getDefaultOperandRepresentation(op_idx)
    return None

def get_base_reg_of_memop(insn):
    """
    For a memory instruction, return the base register string.
    Ghidra PPC: for disp(rB) form, operand layout varies.
    Try operand 2 first (dst, offset, base), then parse operand 1.
    For indexed forms (rA, rB, rC) the base is operand 2.
    """
    n = insn.getNumOperands()
    # Try each operand after the first for something that looks like a register
    # and is used as base. Ghidra usually puts base last for disp(rB) forms.
    for i in range(n - 1, 0, -1):
        s = reg_name(insn, i)
        if s and re.match(r'^r\d+$', s):
            return s
        if s:
            m = re.search(r'\((\w+)\)', s)
            if m:
                return m.group(1)
    return None

def collect_following(insn, n):
    """Return up to n instructions strictly after insn, oldest-first."""
    result = []
    cur = insn.getNext()
    while cur is not None and len(result) < n:
        result.append(cur)
        cur = cur.getNext()
    return result

def run():
    listing = currentProgram.getListing()
    memory  = currentProgram.getMemory()
    patched = 0
    skipped = 0

    for insn in listing.getInstructions(currentProgram.getMinAddress(), True):
        if insn.getMnemonicString().lower() != "extsw":
            continue

        addr = insn.getAddress()

        if insn.getNumOperands() < 2:
            if DEBUG: print("  SKIP %s: fewer than 2 operands" % addr)
            skipped += 1
            continue

        rA = reg_name(insn, 0)
        rS = reg_name(insn, 1)
        if rA != rS:
            if DEBUG: print("  SKIP %s: extsw %s,%s - not identity form (real narrowing)" % (addr, rA, rS))
            skipped += 1
            continue

        orig_bytes = bytearray(4)
        memory.getBytes(addr, orig_bytes)
        orig_word = struct.unpack(">I", bytes(orig_bytes))[0]
        if orig_word == ORI_NOP:
            if DEBUG: print("  SKIP %s: already NOP" % addr)
            continue

        # Scan forward: is rA used as a memory base before being overwritten?
        following = collect_following(insn, SCAN_FORWARD)
        used_as_base   = False
        used_as_base_at = None
        overwritten    = False

        for f in following:
            mnem_f = f.getMnemonicString().lower()
            n_ops  = f.getNumOperands()

            # Check if rA is overwritten (destination of any instruction)
            dst_f = reg_name(f, 0)
            if dst_f == rA:
                overwritten = True
                break

            # Check if rA appears as base register in a memory op
            if mnem_f in MEMORY_OPS:
                base = get_base_reg_of_memop(f)
                if base == rA:
                    used_as_base    = True
                    used_as_base_at = f.getAddress()
                    break

        if not used_as_base:
            if DEBUG:
                reason = "overwritten before memory use" if overwritten else "not used as memory base in window"
                print("  SKIP %s: extsw %s,%s - %s" % (addr, rA, rS, reason))
            skipped += 1
            continue

        # Patch
        orig_hex  = "".join("%02x" % b for b in orig_bytes).upper()
        nop_bytes = bytearray(struct.pack(">I", ORI_NOP))
        try:
            listing.clearCodeUnits(addr, addr, False)
            memory.setBytes(addr, nop_bytes)
            cmd = DisassembleCommand(addr, None, True)
            cmd.applyTo(currentProgram)
            listing.setComment(addr, CodeUnit.EOL_COMMENT,
                "PATCHED extsw->NOP (addr sign-ext, base used @ %s) | ORIG: %s"
                % (used_as_base_at, orig_hex))
            print("  PATCH %s: was %s | %s used as base @ %s"
                  % (addr, orig_hex, rA, used_as_base_at))
            patched += 1
        except Exception as e:
            print("  ERROR %s: %s" % (addr, e))

    print("\nDone. Patched: %d  |  Skipped (real extsw): %d" % (patched, skipped))

run()