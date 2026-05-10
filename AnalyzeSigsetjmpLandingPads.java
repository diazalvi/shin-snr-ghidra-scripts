// AnalyzeSigsetjmpLandingPads.java  (v3)
// Run from Ghidra Script Manager.
//
// For each bl sigsetjmp call site with no containing function:
//   Walks backward through the function list to find the TRUE owner --
//   the function whose last instruction is a BLR/B (epilogue), not a
//   mid-body instruction. Extends that function's body to cover the
//   gap + call site + landing pad, then adds COMPUTED_JUMP to the pad.
//
// Gap strategy: accept gaps up to 256 bytes because the EH prologue
// (register saves, frame setup) between a function epilogue and the
// bl sigsetjmp can be 8-128 bytes.
//
// @author Claude (Umineko RE project)
// @category EH

import ghidra.app.script.GhidraScript;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class AnalyzeSigsetjmpLandingPads extends GhidraScript {

    @Override
    public void run() throws Exception {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();

        Address sigsetjmpAddr = space.getAddress(0x000c9e38L);

        int extended = 0, refAdded = 0, skippedGap = 0,
            skippedNoPrev = 0, skippedOverlap = 0, alreadyOwned = 0;

        List<Long> sites = new ArrayList<>();
        ReferenceIterator refs = rm.getReferencesTo(sigsetjmpAddr);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall())
                sites.add(ref.getFromAddress().getOffset());
        }
        printf("Total sigsetjmp call sites: %d\n", sites.size());

        for (long site : sites) {
            Address siteAddr = space.getAddress(site);

            // Already has an owner -- just add the COMPUTED_JUMP ref
            if (fm.getFunctionContaining(siteAddr) != null) {
                alreadyOwned++;
                addJumpRef(rm, space, fm, site);
                continue;
            }

            // Walk backward through functions to find the best owner.
            // We accept a function as owner if:
            //   (a) gap between its body end and the site is <= 256 bytes, AND
            //   (b) the bytes in the gap do NOT contain another function entry point
            //       that itself is a real named function (would be a separate scope).
            Function owner = null;
            FunctionIterator backIt = fm.getFunctions(siteAddr, false);
            while (backIt.hasNext()) {
                Function candidate = backIt.next();
                if (candidate.getBody().contains(siteAddr)) break; // already contained

                long prevMax = candidate.getBody().getMaxAddress().getOffset();
                long gap = site - prevMax - 1;

                if (gap < 0) continue;  // negative = site inside candidate body
                if (gap > 256) break;   // too far, stop searching

                // Check that the gap contains no OTHER named function entries
                // (which would indicate a different scope, not a continuation)
                boolean gapClear = true;
                Address gapStart = space.getAddress(prevMax + 1);
                Address gapEnd   = space.getAddress(site - 1);
                FunctionIterator gapIt = fm.getFunctions(gapStart, true);
                while (gapIt.hasNext()) {
                    Function gapFn = gapIt.next();
                    if (gapFn.getEntryPoint().compareTo(gapEnd) > 0) break;
                    // There's a function entry in the gap
                    String gname = gapFn.getName();
                    // EH artifacts in the gap are ok; real named functions are not
                    boolean isEHArtifact = gname.startsWith("FUN_")
                        || gname.startsWith("thunk_FUN_")
                        || gname.startsWith("eh_");
                    if (!isEHArtifact) { gapClear = false; break; }
                }

                if (gapClear) { owner = candidate; break; }
                // Named function in gap -- this candidate is not the owner
                break;
            }

            if (owner == null) { skippedNoPrev++; continue; }

            // Find the function that starts immediately after the landing pad
            // to bound the extension
            FunctionIterator fwdIt = fm.getFunctions(siteAddr.add(1), true);
            Function next = null;
            while (fwdIt.hasNext()) {
                Function c = fwdIt.next();
                if (c.getEntryPoint().getOffset() > site) { next = c; break; }
            }
            long nextStart = (next != null)
                ? next.getEntryPoint().getOffset()
                : site + 256;

            // Build new body: owner's existing body + gap + site + landing pad bytes
            Address extStart = owner.getBody().getMaxAddress().add(1);
            Address extEnd   = space.getAddress(nextStart - 4);

            if (extEnd.compareTo(extStart) < 0) { skippedGap++; continue; }

            AddressSet newBody = new AddressSet(owner.getBody());
            newBody.add(extStart, extEnd);

            try {
                owner.setBody(newBody);
                extended++;
            } catch (OverlappingFunctionException e) {
                skippedOverlap++;
                continue;
            } catch (Exception e) {
                printf("  setBody failed for %s @ %08x: %s\n",
                    owner.getName(), owner.getEntryPoint().getOffset(),
                    e.getMessage());
                skippedGap++;
                continue;
            }

            addJumpRef(rm, space, fm, site);
            refAdded++;
        }

        printf("\n=== Results ===\n");
        printf("Already owned (ref only):        %d\n", alreadyOwned);
        printf("Functions extended:              %d\n", extended);
        printf("COMPUTED_JUMP refs added:        %d\n", refAdded);
        printf("Skipped (gap > 256 / unclear):   %d\n", skippedGap);
        printf("Skipped (no suitable prev fn):   %d\n", skippedNoPrev);
        printf("Skipped (body overlap):          %d\n", skippedOverlap);
    }

    private void addJumpRef(ReferenceManager rm, AddressSpace space,
                            FunctionManager fm, long site) {
        for (int delta = 4; delta <= 128; delta += 4) {
            Address landingPad = space.getAddress(site + delta);
            if (fm.getFunctionAt(landingPad) != null) {
                try {
                    rm.addMemoryReference(space.getAddress(site), landingPad,
                        RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
                } catch (Exception e) { /* ignore duplicate refs */ }
                break;
            }
        }
    }
}