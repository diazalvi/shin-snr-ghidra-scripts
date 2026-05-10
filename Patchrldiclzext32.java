// Patchrldiclzext32.java
// Ghidra script: patches rldicl instructions that are pure 64->32 bit zero-extensions
// into semantic no-ops (ori rA,rS,0), leaving an EOL comment with the original encoding.
//
// Criteria for patching:
//   rldicl  rA, rS, SH=0, MB=32
//   -> zeroes the upper 32 bits with no rotation: rA = (uint32_t)rS
//
//   Case 1: rA == rS  -> pure no-op  -> patch to: ori r0,r0,0   (0x60000000)
//   Case 2: rA != rS  -> move+zext   -> patch to: ori rA,rS,0
//   Case 3: Rc=1      -> sets CR0, doing real work -> skip
//
// Works on: current selection, or entire loaded image if nothing is selected.
//
// KEY ENCODING NOTE (rldicl MB field):
//   The PPC ISA encodes MB as a 6-bit field split across the instruction word, but
//   the single "overflow" bit (word bit 5) is the MSB of MB, not the LSB:
//     MB = (bit5 << 5) | bits[10:6]
//   So MB=32=0b100000 -> bit5=1, bits[10:6]=0b00000
//   This gives MATCH_VALUE = 0x78000020 (not 0x78000400 as a naive reading suggests).
//   Verified: 0x78630020 & 0xFC00FFFE = 0x78000020 ✓

//@author
//@category PowerPC
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.util.ArrayList;
import java.util.List;

public class Patchrldiclzext32 extends GhidraScript {

    // rldicl rA,rS,SH,MB instruction word layout (Java int, bit31=MSB):
    //
    //   31-26 : opcode = 30
    //   25-21 : rS
    //   20-16 : rA
    //   15-11 : sh[4:0]   low 5 bits of 6-bit shift amount
    //   10- 6 : mb[4:0]   low 5 bits of 6-bit mask-begin  (ISA: mb[1:5])
    //       5 : mb[5]     MSB of mask-begin               (ISA: mb[0])
    //       4 : sh[5]     MSB of shift amount
    //     3-1 : XO = 0
    //       0 : Rc
    //
    //   MB (decoded) = (bit5 << 5) | bits[10:6]
    //
    //   ZEXT32: SH=0, MB=32=0b100000 -> bit5=1, bits15-11=0, bits10-6=0, bit4=0

    private static final int MASK_RS     = 0x03E00000; // bits 25-21
    private static final int MASK_RA     = 0x001F0000; // bits 20-16
    private static final int MASK_RC     = 0x00000001; // bit 0

    // Match mask: opcode + SH(both halves) + MB(both halves) + XO; excludes rS, rA, Rc
    private static final int MATCH_MASK  = 0xFC000000  // opcode   bits 31-26
                                         | 0x0000F800  // sh[4:0]  bits 15-11
                                         | 0x000007C0  // mb[4:0]  bits 10-6
                                         | 0x00000020  // mb[5]    bit 5
                                         | 0x00000010  // sh[5]    bit 4
                                         | 0x0000000E; // XO       bits 3-1
    // = 0xFC00FFFE

    private static final int MATCH_VALUE = (30 << 26)  // opcode=30 -> 0x78000000
                                         | 0x00000020; // mb[5]=1  -> MB=32
    // = 0x78000020

    // ori rA,rS,0 = opcode(24) | rS<<21 | rA<<16 | imm=0
    private static final int ORI_BASE = (24 << 26); // 0x60000000

    @Override
    public void run() throws Exception {
        Memory  mem     = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        AddressSetView workSet;
        if (currentSelection != null && !currentSelection.isEmpty()) {
            workSet = currentSelection;
            println("Operating on current selection.");
        } else {
            workSet = currentProgram.getMemory().getLoadedAndInitializedAddressSet();
            println("No selection -- scanning entire loaded image.");
        }

        // --- Pass 1: collect candidates ---
        List<Address> candidates = new ArrayList<>();
        monitor.setMessage("Scanning for rldicl ZEXT32 (SH=0, MB=32)...");

        for (AddressRange range : workSet.getAddressRanges()) {
            if (monitor.isCancelled()) break;

            Address cur = range.getMinAddress();
            Address end = range.getMaxAddress();

            // align start to 4-byte boundary
            long off = cur.getOffset();
            if ((off & 3) != 0) {
                try { cur = cur.add(4 - (off & 3)); } catch (Exception e) { continue; }
            }

            while (cur.compareTo(end) <= 0 && !monitor.isCancelled()) {
                if (mem.contains(cur)) {
                    byte[] b = new byte[4];
                    try {
                        if (mem.getBytes(cur, b) == 4) {
                            int word = toInt(b);
                            if ((word & MATCH_MASK) == MATCH_VALUE) {
                                candidates.add(cur);
                            }
                        }
                    } catch (MemoryAccessException e) { /* skip unreadable */ }
                }
                try { cur = cur.add(4); } catch (Exception e) { break; }
            }
        }

        if (candidates.isEmpty()) {
            println("No rldicl ZEXT32 instructions found.");
            return;
        }
        println("Found " + candidates.size() + " candidate(s). Patching...");

        // --- Pass 2: patch ---
        int nNop = 0, nMove = 0, nSkip = 0;

        for (Address addr : candidates) {
            if (monitor.isCancelled()) break;

            byte[] b = new byte[4];
            mem.getBytes(addr, b);
            int word = toInt(b);

            int rS = (word & MASK_RS) >> 21;
            int rA = (word & MASK_RA) >> 16;
            int rc = (word & MASK_RC);

            // Rc=1 (rldicl.) sets CR0 as side-effect -- can't drop
            if (rc != 0) {
                println("  SKIP Rc=1 @ " + addr + "  [" + hex(word) + "]"
                        + "  rldicl. r" + rA + ",r" + rS + ",0,32");
                nSkip++;
                continue;
            }

            String origHex = hex(word);
            int newWord;
            String desc;

            if (rA == rS) {
                // rA = (uint32_t)rA  same register -> pure no-op
                newWord = 0x60000000; // ori r0,r0,0
                desc    = "nop";
                nNop++;
            } else {
                // rA = (uint32_t)rS  different regs -> keep move, drop zext semantics
                newWord = ORI_BASE | (rS << 21) | (rA << 16); // ori rA,rS,0
                desc    = "ori r" + rA + ",r" + rS + ",0";
                nMove++;
            }

           // Write patched instruction
            try {
                // 1. Clear the existing instruction so Ghidra unlocks the bytes
                listing.clearCodeUnits(addr, addr.add(3), false);
                
                // 2. Write the new patched bytes
                mem.setBytes(addr, toBytes(newWord));
            } catch (MemoryAccessException e) {
                println("  ERROR writing @ " + addr + ": " + e.getMessage());
                continue;
            }

            // Append EOL comment with original encoding for easy revert
            CodeUnit cu = listing.getCodeUnitAt(addr);
            if (cu != null) {
                String tag      = "ORIG: " + origHex;
                String existing = cu.getComment(CommentType.EOL);
                String updated;
                if (existing == null || existing.isEmpty()) {
                    updated = tag;
                } else if (existing.contains(origHex)) {
                    updated = existing; // idempotent on re-run
                } else {
                    updated = existing + "  |  " + tag;
                }
                cu.setComment(CommentType.EOL, updated);
            }

            // Refresh disassembly at this address
            disassemble(addr);

            println("  " + addr + "  [" + origHex + "]  rldicl r" + rA + ",r" + rS
                    + ",0,32  ->  " + desc);
        }

        println("\nSummary:");
        println("  Patched as nop  : " + nNop);
        println("  Patched as move : " + nMove);
        println("  Skipped (Rc=1)  : " + nSkip);
    }

    private static int toInt(byte[] b) {
        return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
             | ((b[2] & 0xFF) <<  8) |  (b[3] & 0xFF);
    }

    private static byte[] toBytes(int word) {
        return new byte[]{
            (byte)(word >> 24), (byte)(word >> 16),
            (byte)(word >>  8), (byte)(word      )
        };
    }

    private static String hex(int word) {
        return String.format("%08X", word);
    }
}
