# -*- coding: utf-8 -*-
#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

# -*- coding: utf-8 -*-
# AnnotateBoostFunction.py
# =============================================================================
# Ghidra Jython script for the shin:: PS3 engine (Boost ~1.42, PPC32).
#
# Discovers ALL boost::_bi::bind_t and boost::function instantiations by
# searching for Itanium ABI typeinfo name strings in the binary, then:
#
#   1. Finds the typeinfo struct referencing each string
#   2. Finds the functor_manager function referencing each typeinfo
#   3. Renames unnamed manager functions to functor_manager_<ClassName>
#   4. Walks the 3-level indirection chain to find boost::function vtables
#   5. Creates Ghidra struct types for bind_t, function_buffer, and function
#   6. Annotates vtables with plate comments
#   7. Annotates boost::function assignment sites in decompiled code
#
# Usage: Run from Ghidra Script Manager. Undo-safe (all changes in one tx).
# =============================================================================

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.data import (
    StructureDataType, PointerDataType, Pointer32DataType,
    UnsignedIntegerDataType, BooleanDataType, VoidDataType,
    CategoryPath, DataTypeConflictHandler
)
import re

currentTx = currentProgram.startTransaction("AnnotateBoostFunction")
try:
    fm = currentProgram.getFunctionManager()
    mem = currentProgram.getMemory()
    listing = currentProgram.getListing()
    af = currentProgram.getAddressFactory()
    refMgr = currentProgram.getReferenceManager()
    dtm = currentProgram.getDataTypeManager()

    def addr(offset):
        return af.getDefaultAddressSpace().getAddress(offset)

    def read_u32(address):
        try:
            b = [0] * 4
            for i in range(4):
                b[i] = mem.getByte(address.add(i)) & 0xFF
            return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
        except:
            return None

    def read_cstring(address, maxlen=512):
        chars = []
        for i in range(maxlen):
            try:
                b = mem.getByte(address.add(i)) & 0xFF
            except:
                break
            if b == 0:
                break
            chars.append(chr(b))
        return ''.join(chars)

    # ─────────────────────────────────────────────────────────────────
    # §1  Memory scanning helpers
    # ─────────────────────────────────────────────────────────────────

    # Pre-scan: build a dict of all u32 values in data sections for fast lookup
    print("Building memory index...")
    _u32_index = {}  # value -> [offset, ...]
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        s = block.getStart().getOffset()
        e = block.getEnd().getOffset()
        if (e - s) > 0x200000:
            continue
        off = s
        while off <= e - 3:
            v = read_u32(addr(off))
            if v is not None and v > 0:
                if v not in _u32_index:
                    _u32_index[v] = []
                _u32_index[v].append(off)
            off += 4
    print("  Indexed %d unique values." % len(_u32_index))

    def scan_for_u32(needle):
        return _u32_index.get(needle, [])

    # ─────────────────────────────────────────────────────────────────
    # §2  Demangle and naming helpers
    # ─────────────────────────────────────────────────────────────────

    def demangle_typeinfo(mangled):
        from ghidra.app.util.demangler import DemanglerUtil
        for prefix in ['_ZTI']:
            try:
                result = DemanglerUtil.demangle(currentProgram, prefix + mangled)
                if result:
                    s = str(result)
                    s = s.replace('typeinfo for ', '')
                    return s
            except:
                pass
        return mangled

    def _parse_nested_name(s):
        """Parse Itanium ABI nested name: sequence of <length><ident>."""
        parts = []
        i = 0
        while i < len(s):
            m = re.match(r'(\d+)', s[i:])
            if not m:
                break
            length = int(m.group(1))
            i += len(m.group(1))
            if i + length > len(s):
                break
            parts.append(s[i:i + length])
            i += length
        return parts

    def extract_class_name(mangled):
        """Extract the primary class name for Ghidra identifiers."""
        # PMF: parse class from mfN<R, N<class>E, args>
        mf_match = re.search(r'3mf(\d)I(.)', mangled)
        if mf_match:
            pos = mf_match.end()
            if pos < len(mangled) and mangled[pos] == 'N':
                parts = _parse_nested_name(mangled[pos + 1:])
                if parts:
                    return parts[-1]

        # Free function bind: find first N<nested> after PF
        if 'PF' in mangled and '3_bi' in mangled:
            pf_pos = mangled.index('PF')
            i = pf_pos + 2
            while i < len(mangled):
                if mangled[i] == 'N':
                    p = _parse_nested_name(mangled[i + 1:])
                    skip = {'shin', 'boost', '_bi', 'bind_t', '_mfi',
                            'list0', 'list1', 'list2', 'list3', 'list4',
                            'value', 'arg', 'reference_wrapper'}
                    relevant = [x for x in p if x not in skip]
                    if relevant:
                        return relevant[0]
                    break
                elif mangled[i] in 'RKV':
                    i += 1
                else:
                    i += 1
            return 'fptr'

        # Plain function pointer: PFvvE, PFPN4shin6ISceneEvE
        if mangled.startswith('PF'):
            inner = mangled[2:]
            # Skip P/R/K/V qualifiers to find N
            i = 0
            while i < len(inner) and inner[i] in 'PRKV':
                i += 1
            if i < len(inner) and inner[i] == 'N':
                p = _parse_nested_name(inner[i + 1:])
                relevant = [x for x in p if x != 'shin']
                if relevant:
                    return relevant[-1]
            if 'vv' in mangled:
                return 'void_void'
            return 'fptr'
        return 'unknown'

    def make_short_name(mangled):
        """Build Ghidra-friendly identifier from mangled typeinfo."""
        cls = extract_class_name(mangled)

        mf_match = re.search(r'3mf(\d)', mangled)
        if mf_match:
            arity = mf_match.group(1)
            ret = 'void'
            if 'bind_tIb' in mangled:
                ret = 'bool'
            elif 'bind_tIP' in mangled:
                ret = 'ptr'
            return '%s_mf%s_%s' % (cls, arity, ret)

        if 'PF' in mangled and '3_bi' in mangled:
            ret = 'void'
            if mangled.startswith('N5boost3_bi6bind_tIb'):
                ret = 'bool'
            elif mangled.startswith('N5boost3_bi6bind_tIP'):
                ret = 'ptr'
            list_match = re.search(r'list(\d)', mangled)
            list_arity = list_match.group(1) if list_match else '0'
            return '%s_fptr_%s_l%s' % (cls, ret, list_arity)

        # Plain function pointer (not bind_t)
        if mangled.startswith('PF'):
            return '%s_rawfptr' % cls
        
        return cls

    # ─────────────────────────────────────────────────────────────────
    # §3  Typeinfo → manager → vtable resolution
    # ─────────────────────────────────────────────────────────────────

    def find_typeinfo_structs(str_addr):
        """Find typeinfo structs where [+4] == str_addr."""
        hits = scan_for_u32(str_addr)
        results = []
        for h in hits:
            struct_addr = h - 4
            vtbl = read_u32(addr(struct_addr))
            if vtbl is not None and vtbl > 0x1000:
                results.append(struct_addr)
        return results

    def find_managers_for_typeinfo(typeinfo_addr):
        """Find manager functions that reference a GOT entry pointing to typeinfo."""
        got_hits = scan_for_u32(typeinfo_addr)
        managers = []
        for got_addr in got_hits:
            refs = refMgr.getReferencesTo(addr(got_addr))
            for ref in refs:
                func = fm.getFunctionContaining(ref.getFromAddress())
                if func is not None and func not in managers:
                    managers.append(func)
        return managers

    def find_vtables_for_manager(manager_entry_addr):
        """
        3-level indirection:
          vtable{mgr_toc_desc_ptr, inv_toc_desc_ptr}
            -> TOC_desc{fn_entry, toc}
              -> fn_entry == manager_entry_addr
        """
        results = []
        # Level 1: TOC descriptors where [+0] == manager_entry
        mgr_toc_descs = scan_for_u32(manager_entry_addr)
        if not mgr_toc_descs:
            return results

        # Level 2: pointers to those TOC descriptors = vtable[+0]
        for mgr_desc in mgr_toc_descs:
            vt_hits = scan_for_u32(mgr_desc)
            for vt_addr in vt_hits:
                inv_toc_desc_ptr = read_u32(addr(vt_addr + 4))
                invoker_entry = None
                invoker_fn = None
                if inv_toc_desc_ptr:
                    invoker_entry = read_u32(addr(inv_toc_desc_ptr))
                    if invoker_entry:
                        invoker_fn = fm.getFunctionAt(addr(invoker_entry))
                results.append({
                    'vtable_addr': vt_addr,
                    'manager_toc_desc': mgr_desc,
                    'invoker_entry': invoker_entry,
                    'invoker_fn': invoker_fn,
                })
        return results

    # ─────────────────────────────────────────────────────────────────
    # §4  Classify bind storage kind
    # ─────────────────────────────────────────────────────────────────

    def classify_bind_kind(mangled, manager_func):
        """Determine bind storage kind: pmf, fptr_*, or heap."""
        # Check for heap allocation in manager (operator_new in clone path)
        if manager_func:
            body = manager_func.getBody()
            it = refMgr.getReferenceIterator(body.getMinAddress())
            while it.hasNext():
                ref = it.next()
                if ref.getFromAddress().compareTo(body.getMaxAddress()) > 0:
                    break
                if ref.getReferenceType().isCall():
                    target = fm.getFunctionAt(ref.getToAddress())
                    if target and 'operator_new' in target.getName():
                        return ('heap', 4)

        if mangled.startswith('PF'):
            return ('fptr_1arg', 8)

        if re.search(r'3mf\d', mangled):
            return ('pmf', 12)

        if 'reference_wrapper' in mangled:
            if 'list3' in mangled:
                return ('fptr_3arg', 12)
            return ('fptr_2arg', 12)

        if 'list1' in mangled and 'value' not in mangled:
            return ('fptr_1arg', 8)

        return ('pmf', 12)

    # ─────────────────────────────────────────────────────────────────
    # §5  Create Ghidra data types
    # ─────────────────────────────────────────────────────────────────

    def create_buffer_type(short_name, bind_kind, buf_size):
        cat = get_or_create_cat("/boost/function")
        name = "boost_function_buffer_%s" % short_name
        existing = dtm.getDataType(cat, name)
        if existing is not None:
            return existing

        s = StructureDataType(cat, name, 0)
        if bind_kind == 'pmf':
            s.add(UnsignedIntegerDataType.dataType, 4, "pmf_ptr",
                  "Itanium PMF: fn entry or vtable_offset|1")
            s.add(UnsignedIntegerDataType.dataType, 4, "pmf_adj",
                  "Itanium PMF: this-pointer adjustment")
            s.add(Pointer32DataType.dataType, 4, "obj_ptr",
                  "Bound this pointer")
        elif bind_kind in ('fptr_2arg', 'fptr_3arg'):
            s.add(Pointer32DataType.dataType, 4, "fn_ptr", "Free function TOC desc")
            s.add(Pointer32DataType.dataType, 4, "bound_arg0", "Bound arg 0")
            s.add(UnsignedIntegerDataType.dataType, 4, "bound_arg1", "Bound arg 1")
        elif bind_kind == 'fptr_1arg':
            s.add(Pointer32DataType.dataType, 4, "fn_ptr", "Function TOC desc")
            s.add(UnsignedIntegerDataType.dataType, 4, "padding", "")
        elif bind_kind == 'heap':
            s.add(Pointer32DataType.dataType, 4, "heap_ptr",
                  "Pointer to heap-allocated bind_t")
        else:
            for i in range(buf_size // 4):
                s.add(UnsignedIntegerDataType.dataType, 4, "field_%d" % i, "")
        return dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)

    def create_vtable_type(short_name):
        cat = get_or_create_cat("/boost/function")
        name = "boost_function_vtable_%s" % short_name
        existing = dtm.getDataType(cat, name)
        if existing is not None:
            return existing
        s = StructureDataType(cat, name, 0)
        s.add(Pointer32DataType.dataType, 4, "manager_desc",
              "TOC desc ptr -> manager()")
        s.add(Pointer32DataType.dataType, 4, "invoker_desc",
              "TOC desc ptr -> invoker()")
        return dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)

    def create_function_type(short_name, buffer_type):
        cat = get_or_create_cat("/boost/function")
        name = "boost_function_%s" % short_name
        existing = dtm.getDataType(cat, name)
        if existing is not None:
            return existing
        vtbl = create_vtable_type(short_name)
        s = StructureDataType(cat, name, 0)
        s.add(Pointer32DataType(vtbl), 4, "vtable",
              "Tagged ptr; NULL=empty, &1=trivial")
        s.add(buffer_type, buffer_type.getLength(), "functor",
              "Inline bind_t storage")
        return dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)

    def create_bind_type(short_name, bind_kind):
        cat = get_or_create_cat("/boost/_bi")
        name = "bind_t_%s" % short_name
        existing = dtm.getDataType(cat, name)
        if existing is not None:
            return existing
        s = StructureDataType(cat, name, 0)
        if bind_kind == 'pmf':
            s.add(UnsignedIntegerDataType.dataType, 4, "pmf_ptr", "Member fn ptr")
            s.add(UnsignedIntegerDataType.dataType, 4, "pmf_adj", "this adjustment")
            s.add(Pointer32DataType.dataType, 4, "this_ptr", "Bound object")
        elif bind_kind in ('fptr_2arg', 'fptr_3arg'):
            s.add(Pointer32DataType.dataType, 4, "fn_ptr", "Function pointer")
            s.add(Pointer32DataType.dataType, 4, "bound_arg0", "Arg 0")
            s.add(UnsignedIntegerDataType.dataType, 4, "bound_arg1", "Arg 1")
        elif bind_kind == 'fptr_1arg':
            s.add(Pointer32DataType.dataType, 4, "fn_ptr", "Function pointer")
            s.add(UnsignedIntegerDataType.dataType, 4, "padding", "")
        elif bind_kind == 'heap':
            s.add(Pointer32DataType.dataType, 4, "data_ptr", "Heap data")
        return dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)

    def get_or_create_cat(path_str):
        return CategoryPath(path_str)

    # ─────────────────────────────────────────────────────────────────
    # §6  Rename helpers
    # ─────────────────────────────────────────────────────────────────

    def rename_if_unnamed(func, new_name, force=False):
        if func is None:
            return False
        old = func.getName()
        if not force and not old.startswith('FUN_') and not old.startswith('thunk_FUN_'):
            return False
        if old == new_name:
            return False
        # Also force-rename if old name contains 'unknown'
        if not force and 'unknown' not in old:
            if not old.startswith('FUN_') and not old.startswith('thunk_FUN_'):
                return False
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            return True
        except:
            try:
                func.setName('%s_%08x' % (new_name,
                             func.getEntryPoint().getOffset()),
                            SourceType.USER_DEFINED)
                return True
            except:
                return False

    # ─────────────────────────────────────────────────────────────────
    # §7  Annotate assignment sites
    # ─────────────────────────────────────────────────────────────────

    def annotate_assignment_sites(vtable_addr, entry):
        """Find code that loads the vtable PTR_PTR and place comments."""
        count = 0
        ptr_ptrs = scan_for_u32(vtable_addr)
        for pp_addr in ptr_ptrs:
            refs = refMgr.getReferencesTo(addr(pp_addr))
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = fm.getFunctionContaining(from_addr)
                if func is None:
                    continue
                comment = ('boost::function assignment: %s\n'
                           '  = boost::bind(...)  [%s]\n'
                           '  %s' % (entry['short_name'],
                                     entry['bind_kind'],
                                     entry['demangled']))
                try:
                    listing.setComment(from_addr, CodeUnit.PRE_COMMENT,
                                      comment)
                    count += 1
                except:
                    pass
        return count

    # ═════════════════════════════════════════════════════════════════
    # MAIN
    # ═════════════════════════════════════════════════════════════════

    print("=" * 72)
    print("Boost.Function / Boost.Bind Annotation Script (string-based)")
    print("=" * 72)

    # ── Step 1: Find all typeinfo strings ──────────────────────────
    print("\n[1/6] Searching for typeinfo name strings...")

    typeinfo_strings = []
    seen_mangled = set()

    # Search using Ghidra's memory search for the bind_t prefix
    bind_prefix = bytearray(b'N5boost3_bi6bind_t')
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()
        found = start
        while True:
            try:
                found = mem.findBytes(found, end, bind_prefix, None, True, None)
            except:
                break
            if found is None:
                break
            s = read_cstring(found, 256)
            if s and s not in seen_mangled:
                seen_mangled.add(s)
                typeinfo_strings.append({
                    'address': found.getOffset(),
                    'mangled': s,
                })
            try:
                found = found.add(1)
            except:
                break

    # Also search for plain function pointer typeinfos: PFvvE, PFPN...
    for pf_prefix in [bytearray(b'PFvvE'), bytearray(b'PFPN')]:
        for block in mem.getBlocks():
            if not block.isInitialized():
                continue
            start = block.getStart()
            end = block.getEnd()
            found = start
            while True:
                try:
                    found = mem.findBytes(found, end, pf_prefix, None, True, None)
                except:
                    break
                if found is None:
                    break
                s = read_cstring(found, 256)
                if s and s.startswith('PF') and s.endswith('E') and s not in seen_mangled:
                    seen_mangled.add(s)
                    typeinfo_strings.append({
                        'address': found.getOffset(),
                        'mangled': s,
                    })
                try:
                    found = found.add(1)
                except:
                    break

    print("  Found %d unique typeinfo strings." % len(typeinfo_strings))

    for ts in typeinfo_strings:
        print("    0x%08x: %s" % (ts['address'], ts['mangled'][:80]))

    # ── Step 2: Resolve typeinfo → manager ─────────────────────────
    print("\n[2/6] Resolving typeinfo structs -> manager functions...")

    all_entries = []
    for ts in typeinfo_strings:
        mangled = ts['mangled']
        str_addr = ts['address']
        demangled = demangle_typeinfo(mangled)
        short_name = make_short_name(mangled)

        ti_addrs = find_typeinfo_structs(str_addr)
        managers = []
        for ti in ti_addrs:
            for m in find_managers_for_typeinfo(ti):
                if m not in managers:
                    managers.append(m)

        entry = {
            'mangled': mangled,
            'demangled': demangled,
            'short_name': short_name,
            'str_addr': str_addr,
            'typeinfo_addrs': ti_addrs,
            'managers': managers,
        }
        all_entries.append(entry)

    # Deduplicate short_names by appending a suffix for collisions
    name_counts = {}
    for entry in all_entries:
        n = entry['short_name']
        name_counts[n] = name_counts.get(n, 0) + 1
    name_seen = {}
    for entry in all_entries:
        n = entry['short_name']
        if name_counts[n] > 1:
            idx = name_seen.get(n, 0)
            name_seen[n] = idx + 1
            if idx > 0:
                entry['short_name'] = '%s_%d' % (n, idx)
        mgr_str = ', '.join(['%s@%08x' % (m.getName(), m.getEntryPoint().getOffset())
                            for m in entry['managers']]) if entry['managers'] else '(none)'
        print("  %-45s -> %s" % (entry['short_name'], mgr_str))

    # ── Step 3: Rename unnamed managers ────────────────────────────
    print("\n[3/9] Renaming unnamed manager functions...")
    renamed = 0
    for entry in all_entries:
        for mgr in entry['managers']:
            name = 'functor_manager_%s' % entry['short_name']
            if rename_if_unnamed(mgr, name):
                renamed += 1
                print("  FUN_%08x -> %s" % (
                    mgr.getEntryPoint().getOffset(), name))
    print("  Renamed %d function(s)." % renamed)
    
    # Set correct prototypes on all manager functions
    # Manager signature: void manager(void* src_buf, void* dst_buf, int op)
    print("  Setting manager prototypes...")
    mgr_proto_set = 0
    for entry in all_entries:
        for mgr in entry['managers']:
            try:
                from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
                from ghidra.program.model.data import (
                    FunctionDefinitionDataType, ParameterDefinitionImpl
                )
                # Build prototype: void manager(void* src, void* dst, int op)
                fdt = FunctionDefinitionDataType(mgr.getName())
                fdt.setReturnType(VoidDataType.dataType)
                params = [
                    ParameterDefinitionImpl("src_buf", Pointer32DataType.dataType, "Source buffer"),
                    ParameterDefinitionImpl("dst_buf", Pointer32DataType.dataType, "Dest buffer / output"),
                    ParameterDefinitionImpl("op", UnsignedIntegerDataType.dataType, "functor_manager_operation_type"),
                ]
                fdt.setArguments(params)
                cmd = ApplyFunctionSignatureCmd(
                    mgr.getEntryPoint(), fdt, SourceType.USER_DEFINED)
                cmd.applyTo(currentProgram)
                mgr_proto_set += 1
            except:
                pass
    print("  Set %d manager prototype(s)." % mgr_proto_set)

    # ── Step 4: Find vtables ───────────────────────────────────────
    print("\n[4/9] Finding boost::function vtables...")
    all_vtables = []
    for entry in all_entries:
        for mgr in entry['managers']:
            vtables = find_vtables_for_manager(mgr.getEntryPoint().getOffset())
            for vt in vtables:
                inv = vt['invoker_fn']
                inv_name = inv.getName() if inv else 'FUN_%08x' % (vt['invoker_entry'] or 0)
                print("  %-45s vt@0x%08x  inv=%s" % (
                    entry['short_name'], vt['vtable_addr'], inv_name))
                all_vtables.append({
                    'entry': entry,
                    'vtable_addr': vt['vtable_addr'],
                    'invoker_entry': vt['invoker_entry'],
                    'invoker_fn': vt['invoker_fn'],
                    'manager': mgr,
                })
    print("  Found %d vtable(s) total." % len(all_vtables))

    # ── Step 5: Rename invoker functions ───────────────────────────
    print("\n[5/9] Renaming invoker functions...")
    inv_renamed = 0
    seen_invokers = set()
    for vt_info in all_vtables:
        inv = vt_info['invoker_fn']
        if inv is None:
            continue
        entry_addr = inv.getEntryPoint().getOffset()
        if entry_addr in seen_invokers:
            continue
        seen_invokers.add(entry_addr)
        
        entry = vt_info['entry']
        inv_name = 'boost_invoker_%s' % entry['short_name']
        if rename_if_unnamed(inv, inv_name):
            inv_renamed += 1
            print("  FUN_%08x -> %s" % (entry_addr, inv_name))
    print("  Renamed %d invoker(s)." % inv_renamed)
    renamed += inv_renamed

    # ── Step 6: Identify and prototype store_args / noop helpers ────
    print("\n[6/9] Typing store_args and noop helpers...")
    helper_renamed = 0
    
    # For each vtable assignment site, find the store_args call in the
    # same function. The pattern is always:
    #   store_args(&bind_buf, pmf_or_fptr, obj_ptr)  ← store_args call
    #   ...
    #   local_vtable = PTR_PTR_XXXX                   ← vtable assignment
    #
    # We map: store_args_func_addr -> [(entry, caller_func, call_addr)]
    store_args_map = {}  # fn_addr -> [{'entry': ..., 'func': ..., 'call_addr': ...}]
    noop_set = set()  # addresses of confirmed noop (blr) functions
    
    for vt_info in all_vtables:
        vt_addr = vt_info['vtable_addr']
        entry = vt_info['entry']
        ptr_ptrs = scan_for_u32(vt_addr)
        
        for pp_addr in ptr_ptrs:
            refs = refMgr.getReferencesTo(addr(pp_addr))
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = fm.getFunctionContaining(from_addr)
                if func is None:
                    continue
                
                # Scan all calls in this function
                body = func.getBody()
                it = refMgr.getReferenceIterator(body.getMinAddress())
                while it.hasNext():
                    r = it.next()
                    if r.getFromAddress().compareTo(body.getMaxAddress()) > 0:
                        break
                    if not r.getReferenceType().isCall():
                        continue
                    target = fm.getFunctionAt(r.getToAddress())
                    if target is None:
                        continue
                    taddr = target.getEntryPoint().getOffset()
                    tname = target.getName()
                    
                    # Identify noops: single blr instruction
                    first_instr = read_u32(addr(taddr))
                    if first_instr == 0x4e800020:  # blr
                        tbody = target.getBody()
                        tsize = tbody.getMaxAddress().getOffset() - tbody.getMinAddress().getOffset()
                        if tsize <= 8:
                            noop_set.add(taddr)
                    
                    # Identify store_args: named 'store_args' or 'boost_bind'
                    # or small unnamed functions that aren't noops
                    is_store = False
                    if 'store_args' in tname or tname == 'boost_bind':
                        is_store = True
                    elif tname.startswith('FUN_'):
                        # Check if it's a small store function (not a noop)
                        tbody = target.getBody()
                        tsize = tbody.getMaxAddress().getOffset() - tbody.getMinAddress().getOffset()
                        if 8 < tsize <= 24 and taddr not in noop_set:
                            # Verify: function should store r4->r3[0], r5->r3[1]
                            # Read first few instructions
                            i0 = read_u32(addr(taddr))
                            i1 = read_u32(addr(taddr + 4))
                            # PPC stw r4,0(r3) = 0x90830000
                            # PPC stw r5,4(r3) = 0x90a30004
                            # PPC stw r5,8(r3) = 0x90a30008
                            if i0 is not None and (i0 & 0xFC000000) == 0x90000000:
                                # It's a store instruction — likely store_args
                                is_store = True
                    
                    if is_store:
                        if taddr not in store_args_map:
                            store_args_map[taddr] = []
                        # Avoid duplicates
                        already = False
                        for existing in store_args_map[taddr]:
                            if (existing['entry']['short_name'] == entry['short_name'] and
                                existing['func'].getEntryPoint().getOffset() == func.getEntryPoint().getOffset()):
                                already = True
                                break
                        if not already:
                            store_args_map[taddr] = store_args_map.get(taddr, [])
                            store_args_map[taddr].append({
                                'entry': entry,
                                'func': func,
                                'call_addr': r.getFromAddress().getOffset(),
                            })
    
    # Rename noops
    for noop_addr in noop_set:
        func = fm.getFunctionAt(addr(noop_addr))
        if func and rename_if_unnamed(func, 'boost_function_noop_%08x' % noop_addr):
            helper_renamed += 1
            print("  FUN_%08x -> boost_function_noop (blr)" % noop_addr)
    
    # For each store_args function, determine the bind type(s) it serves
    # and set its prototype
    for sa_addr, usages in store_args_map.items():
        sa_func = fm.getFunctionAt(addr(sa_addr))
        if sa_func is None:
            continue
        
        # Determine the bind_t type from the entries that use this store_args
        # If multiple different entries use it, use the first one (they share layout)
        if not usages:
            continue
        primary_entry = usages[0]['entry']
        bind_kind = primary_entry.get('bind_kind', 'pmf')
        bind_type = primary_entry.get('bind_type')
        short_name = primary_entry['short_name']
        
        # Extract the bound class name from the mangled string for the prototype
        mangled = primary_entry['mangled']
        cls_name = extract_class_name(mangled)
        
        # Determine parameter types based on bind_kind
        if bind_kind == 'pmf':
            # store_args3: bind_buf, pmf_toc_desc, this_ptr
            # The PMF is a TOC descriptor pointer (void*)
            # The this_ptr is a pointer to the class
            proto_comment = (
                '%s * boost_bind(\n'
                '    %s *bind_buf,\n'
                '    void *pmf_toc_desc,  /* &%s::method */\n'
                '    %s *this_ptr\n'
                ')' % (bind_type.getName() if bind_type else 'bind_t',
                       bind_type.getName() if bind_type else 'bind_t',
                       cls_name, cls_name))
        elif bind_kind in ('fptr_2arg', 'fptr_3arg'):
            # store_args2/3: bind_buf, fn_toc_desc, ref(obj)
            proto_comment = (
                '%s * boost_bind(\n'
                '    %s *bind_buf,\n'
                '    void *fn_toc_desc,  /* free function */\n'
                '    %s *bound_ref\n'
                ')' % (bind_type.getName() if bind_type else 'bind_t',
                       bind_type.getName() if bind_type else 'bind_t',
                       cls_name))
        elif bind_kind == 'fptr_1arg':
            proto_comment = (
                '%s * boost_bind(\n'
                '    %s *bind_buf,\n'
                '    void *fn_toc_desc\n'
                ')' % (bind_type.getName() if bind_type else 'bind_t',
                       bind_type.getName() if bind_type else 'bind_t'))
        elif bind_kind == 'heap':
            proto_comment = (
                '%s * boost_bind(\n'
                '    %s *bind_buf,\n'
                '    void *fn_toc_desc,\n'
                '    void *bound_data  /* heap-allocated */\n'
                ')' % (bind_type.getName() if bind_type else 'bind_t',
                       bind_type.getName() if bind_type else 'bind_t'))
        else:
            proto_comment = 'bind_t * boost_bind(bind_t *buf, void *fn, void *obj)'
        
        # Set plate comment on the store_args function
        try:
            existing_comment = listing.getComment(addr(sa_addr), CodeUnit.PLATE_COMMENT)
            if existing_comment is None or 'boost_bind' not in (existing_comment or ''):
                listing.setComment(addr(sa_addr), CodeUnit.PLATE_COMMENT,
                    'boost::bind store_args helper\n'
                    'Used by: %s\n'
                    'Effective prototype:\n%s' % (
                        ', '.join(set(u['entry']['short_name'] for u in usages)),
                        proto_comment))
        except:
            pass
        
        # Try to set the actual function prototype
        if bind_type:
            bt_ptr_name = bind_type.getName() + ' *'
            if bind_kind == 'pmf':
                proto_str = '%s boost_bind(%s bind_buf, void * pmf_desc, void * this_ptr)' % (
                    bt_ptr_name, bt_ptr_name)
            elif bind_kind in ('fptr_2arg', 'fptr_3arg'):
                proto_str = '%s boost_bind(%s bind_buf, void * fn_desc, void * bound_ref)' % (
                    bt_ptr_name, bt_ptr_name)
            else:
                proto_str = '%s boost_bind(%s bind_buf, void * fn_desc)' % (
                    bt_ptr_name, bt_ptr_name)
            
            try:
                from ghidra.program.model.listing import FunctionSignature
                sa_func.setCustomVariableStorage(False)
                # Set prototype via the function's signature
                from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
                from ghidra.program.model.data import FunctionDefinitionDataType
                # Simpler: just set the return type and rename params
                if bind_type:
                    sa_func.setReturnType(
                        PointerDataType(Pointer32DataType(bind_type)),
                        SourceType.USER_DEFINED)
            except:
                pass
        
        # Annotate each call site with the specific concrete types
        for usage in usages:
            e = usage['entry']
            call_addr = usage['call_addr']
            caller = usage['func']
            
            if bind_kind == 'pmf':
                call_comment = (
                    'boost::bind(&%s::method, this_ptr, _1...)\n'
                    '  bind_t = %s\n'
                    '  %s' % (cls_name, e['short_name'], e['demangled']))
            elif bind_kind in ('fptr_2arg', 'fptr_3arg'):
                call_comment = (
                    'boost::bind(&free_fn, ref(%s), _1...)\n'
                    '  bind_t = %s\n'
                    '  %s' % (cls_name, e['short_name'], e['demangled']))
            else:
                call_comment = (
                    'boost::bind(&fn)\n'
                    '  bind_t = %s\n'
                    '  %s' % (e['short_name'], e['demangled']))
            
            try:
                listing.setComment(addr(call_addr), CodeUnit.PRE_COMMENT, call_comment)
            except:
                pass
        
        sa_name = sa_func.getName()
        bind_types_str = ', '.join(set(u['entry']['short_name'] for u in usages))
        print("  %-40s -> %s  (used by: %s)" % (
            sa_name, proto_comment.split('\n')[0], bind_types_str))
    
    print("  Processed %d store_args function(s), %d noop(s)." % (
        len(store_args_map), len(noop_set)))
    renamed += helper_renamed

    # ── Step 7: Create data types ──────────────────────────────────
    print("\n[7/9] Creating Ghidra data types...")
    type_count = 0
    for entry in all_entries:
        mgr = entry['managers'][0] if entry['managers'] else None
        bind_kind, buf_size = classify_bind_kind(entry['mangled'], mgr)
        entry['bind_kind'] = bind_kind

        buf_t = create_buffer_type(entry['short_name'], bind_kind, buf_size)
        func_t = create_function_type(entry['short_name'], buf_t)
        bind_t = create_bind_type(entry['short_name'], bind_kind)
        vtbl_t = create_vtable_type(entry['short_name'])

        entry['buffer_type'] = buf_t
        entry['function_type'] = func_t
        entry['bind_type'] = bind_t
        entry['vtable_type'] = vtbl_t
        type_count += 4

        print("  %-45s %s (%dB)" % (entry['short_name'], bind_kind, buf_size))
    print("  Created %d type(s)." % type_count)

    # ── Step 8: Identify locals for retyping ─────────────────────────
    print("\n[8/9] Identifying local variables for retyping...")
    from ghidra.app.decompiler import DecompInterface

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    
    retype_report = []  # [(func_addr, func_name, var_name, boost_type_name)]
    
    # For each vtable, find assignment sites and identify the local vars
    seen_funcs = set()
    for vt_info in all_vtables:
        entry = vt_info['entry']
        vt_addr = vt_info['vtable_addr']
        func_type = entry.get('function_type')
        if func_type is None:
            continue
        
        ptr_ptrs = scan_for_u32(vt_addr)
        for pp_addr in ptr_ptrs:
            refs = refMgr.getReferencesTo(addr(pp_addr))
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = fm.getFunctionContaining(from_addr)
                if func is None:
                    continue
                func_key = func.getEntryPoint().getOffset()
                if func_key in seen_funcs:
                    continue
                seen_funcs.add(func_key)
                
                try:
                    result = decomp.decompileFunction(func, 30, None)
                    if result is None or not result.decompileCompleted():
                        continue
                    hfunc = result.getHighFunction()
                    if hfunc is None:
                        continue
                    
                    # Find the local variable that receives the vtable ptr
                    # by looking for COPY operations from the PTR_PTR address
                    lsm = hfunc.getLocalSymbolMap()
                    for sym in lsm.getSymbols():
                        name = sym.getName()
                        storage = sym.getStorage()
                        if storage is None or not storage.isStackStorage():
                            continue
                        dt = sym.getDataType()
                        if dt is None:
                            continue
                        
                        # Look for the vtable pointer variable:
                        # It's any stack local that gets assigned from PTR_PTR_*
                        # Could be default local_XX or already retyped boost_func_*
                        if not (name.startswith('local_') or 
                                name.startswith('boost_func_') or
                                name.startswith('uStack_') or
                                name.startswith('iStack_')):
                            continue
                        # Skip if already correctly typed
                        if dt.getName() == func_type.getName():
                            continue
                        # Accept if it's a 4-byte ptr or already partially typed
                        if dt.getLength() > func_type.getLength():
                            continue
                            # Check high variable's defining pcode ops
                            hv = sym.getHighVariable()
                            if hv is None:
                                continue
                            # Check if any instance references our PTR_PTR
                            for inst in hv.getInstances():
                                defn = inst.getDef()
                                if defn is None:
                                    continue
                                # Look for COPY or STORE from the PTR_PTR addr
                                inputs = defn.getInputs()
                                for inp in inputs:
                                    a = inp.getAddress()
                                    if a is not None:
                                        off = a.getOffset()
                                        if off in [pp_addr, pp_addr & 0xFFFFFFFF]:
                                            retype_report.append((
                                                func_key,
                                                func.getName(),
                                                name,
                                                func_type.getName(),
                                                entry['short_name']
                                            ))
                except Exception as ex:
                    pass
    
    decomp.dispose()

    if retype_report:
        print("  Found %d local variable(s) to retype:" % len(retype_report))
        for (fa, fn, vn, tn, sn) in retype_report:
            print("    %s @ 0x%08x: %s -> %s" % (fn, fa, vn, tn))
        
        # Actually apply the retypes
        retyped = 0
        for (fa, fn, vn, tn, sn) in retype_report:
            try:
                func = fm.getFunctionAt(addr(fa))
                if func is None:
                    continue
                entry_match = None
                for e in all_entries:
                    if e['short_name'] == sn:
                        entry_match = e
                        break
                if not entry_match or 'function_type' not in entry_match:
                    continue
                
                new_type = entry_match['function_type']
                new_size = new_type.getLength()
                
                # Find the target variable and its stack offset
                target_var = None
                target_offset = None
                for var in func.getAllVariables():
                    if var.getName() == vn and var.isStackVariable():
                        target_var = var
                        target_offset = var.getStackOffset()
                        break
                
                if target_var is None or target_offset is None:
                    continue
                
                # Ghidra aligns stack variables to 4-byte boundaries.
                # local_5c at getStackOffset()=-0x5c actually occupies
                # Stack[-0x60] when stored. We must check the ALIGNED
                # range for conflicts.
                # Align down (toward more negative): e.g. -0x5c -> -0x5c & ~3 = -0x5c
                # But Ghidra may round further. To be safe, extend the
                # conflict zone by 4 bytes in each direction.
                check_start = target_offset - 4  # extra margin below
                check_end = target_offset + new_size + 4  # extra margin above
                
                # Remove all conflicting variables in the expanded range.
                # Retry since removing vars can change the list.
                removed_total = 0
                for attempt in range(10):
                    conflicts = []
                    for var in func.getAllVariables():
                        if var == target_var:
                            continue
                        if not var.isStackVariable():
                            continue
                        vo = var.getStackOffset()
                        vs = var.getLength()
                        # Liberal overlap check with margin
                        if vo < check_end and vo + vs > check_start:
                            conflicts.append(var)
                    if not conflicts:
                        break
                    for cv in conflicts:
                        try:
                            func.removeVariable(cv)
                            removed_total += 1
                        except:
                            pass
                
                # Apply the new type
                try:
                    target_var.setDataType(new_type, SourceType.USER_DEFINED)
                    retyped += 1
                    if removed_total:
                        print("    Applied: %s.%s = %s (removed %d conflicts)" % (
                            fn, vn, tn, removed_total))
                    else:
                        print("    Applied: %s.%s = %s" % (fn, vn, tn))
                except Exception as ex2:
                    print("    Failed: %s.%s: %s" % (fn, vn, str(ex2)))
            except Exception as ex_outer:
                print("    Error: %s.%s: %s" % (fn, vn, str(ex_outer)))
        
        print("  Retyped %d variable(s)." % retyped)
    else:
        print("  No automatic retype candidates found.")
        print("  TIP: In functions with boost::function assignment comments,")
        print("       retype the vtable local + adjacent buffer locals as")
        print("       the boost_function_<Name> struct from /boost/function/")

    # ── Step 9: Flow overrides, equates, bind buffer & local renaming ─
    print("\n[9/10] Setting call overrides, equates, bind buffer types, and local names...")
    from ghidra.program.model.symbol import RefType
    
    eqTbl = currentProgram.getEquateTable()
    
    # Ensure equates exist for functor_manager_operation_type
    eq_names = {
        0: 'clone_functor_tag',
        1: 'move_functor_tag',
        2: 'destroy_functor_tag',
        3: 'check_functor_type_tag',
        4: 'get_functor_type_tag',
    }
    equates = {}
    for val, name in eq_names.items():
        eq = eqTbl.getEquate(name)
        if eq is None:
            try:
                eq = eqTbl.createEquate(name, val)
            except:
                pass
        equates[val] = eq
    
    overrides_set = 0
    equates_set = 0
    bind_bufs_retyped = 0
    locals_renamed = 0
    
    # For each function that has a vtable assignment, scan for:
    # 1. bctrl instructions → potential manager/invoker indirect calls
    # 2. li rN, <constant> just before bctrl → equate candidates
    # 3. Local bind buffer variables adjacent to the boost::function local
    
    seen_override_funcs = set()
    
    for vt_info in all_vtables:
        entry = vt_info['entry']
        vt_addr = vt_info['vtable_addr']
        mgr = vt_info['manager']
        inv_fn = vt_info['invoker_fn']
        inv_entry = vt_info['invoker_entry']
        
        ptr_ptrs = scan_for_u32(vt_addr)
        for pp_addr in ptr_ptrs:
            refs = refMgr.getReferencesTo(addr(pp_addr))
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = fm.getFunctionContaining(from_addr)
                if func is None:
                    continue
                func_key = func.getEntryPoint().getOffset()
                if func_key in seen_override_funcs:
                    continue
                seen_override_funcs.add(func_key)
                
                body = func.getBody()
                
                # Scan for bctrl instructions (PPC opcode 0x4e800421)
                cur = body.getMinAddress()
                while cur is not None and cur.compareTo(body.getMaxAddress()) <= 0:
                    instr = listing.getInstructionAt(cur)
                    if instr is None:
                        try:
                            cur = cur.add(4)
                        except:
                            break
                        continue
                    
                    mnemonic = instr.getMnemonicString()
                    
                    # Look for bctrl (indirect call via CTR register)
                    if mnemonic == 'bctrl':
                        bctrl_addr = cur
                        
                        # Check if this bctrl is near our vtable reference
                        # (within ~256 bytes of the vtable load)
                        dist = abs(bctrl_addr.getOffset() - from_addr.getOffset())
                        if dist > 512:
                            try:
                                cur = cur.add(4)
                            except:
                                break
                            continue
                        
                        # Search backwards for a 'li rN, <constant>' that loads
                        # the functor_manager_operation_type argument (r5 typically)
                        scan_addr = bctrl_addr
                        op_value = None
                        for back in range(20):
                            try:
                                scan_addr = scan_addr.add(-4)
                            except:
                                break
                            prev_instr = listing.getInstructionAt(scan_addr)
                            if prev_instr is None:
                                continue
                            prev_mn = prev_instr.getMnemonicString()
                            if prev_mn == 'li':
                                # Check if it's loading into r5 (arg3)
                                # Operand 0 = register, operand 1 = immediate
                                try:
                                    reg = prev_instr.getRegister(0)
                                    if reg is not None and reg.getName() == 'r5':
                                        imm = prev_instr.getScalar(1)
                                        if imm is not None:
                                            op_value = int(imm.getValue())
                                            
                                            # Set equate
                                            if op_value in equates and equates[op_value] is not None:
                                                try:
                                                    equates[op_value].addReference(scan_addr, 1)
                                                    equates_set += 1
                                                except:
                                                    pass
                                            break
                                except:
                                    pass
                        
                        # Set CALL_OVERRIDE_UNCONDITIONAL reference.
                        # This is a RefType (not FlowOverride!) that tells
                        # the decompiler to treat this bctrl as a direct
                        # call to the target function.
                        if op_value is not None and op_value in (0, 2):
                            # This is a manager call (clone=0 or destroy=2)
                            try:
                                # Remove ALL existing references from this bctrl
                                existing_refs = list(refMgr.getReferencesFrom(bctrl_addr))
                                for old_ref in existing_refs:
                                    refMgr.delete(old_ref)
                                
                                # Add CALL_OVERRIDE_UNCONDITIONAL ref
                                refMgr.addMemoryReference(
                                    bctrl_addr,
                                    mgr.getEntryPoint(),
                                    RefType.CALL_OVERRIDE_UNCONDITIONAL,
                                    SourceType.USER_DEFINED, 0)
                                overrides_set += 1
                            except Exception as oe:
                                print("    Override failed at 0x%08x: %s" % (
                                    bctrl_addr.getOffset(), str(oe)))
                    
                    try:
                        cur = cur.add(instr.getLength())
                    except:
                        break
                
                # Also scan for bctrl that dispatches through the invoker
                # These are in the CFuncTask execute path, not directly in
                # the constructor. We handle invoker overrides separately below.
                
                # --- Rename local variables ---
                # Rename the boost::function local to boost_func_<short_name>
                try:
                    for var in func.getAllVariables():
                        if not var.isStackVariable():
                            continue
                        dt = var.getDataType()
                        if dt is None:
                            continue
                        dt_name = dt.getName()
                        var_name = var.getName()
                        
                        # Rename boost::function struct locals
                        if dt_name.startswith('boost_function_') and var_name.startswith('local_'):
                            short = dt_name.replace('boost_function_', '')
                            new_name = 'boost_func_%s' % short
                            try:
                                var.setName(new_name, SourceType.USER_DEFINED)
                                locals_renamed += 1
                            except:
                                pass
                except:
                    pass
    
    # --- Retype bind buffer locals ---
    # The bind buffer is the args to store_args3/store_args2.
    # It's typically 3 consecutive locals (for PMF) or 2 (for fptr).
    # These are at the stack offset just above the boost::function local.
    # We identify them by finding the store_args call and checking
    # what stack address r3 points to.
    for sa_addr_val, usages in store_args_map.items():
        if not usages:
            continue
        primary = usages[0]['entry']
        bind_type = primary.get('bind_type')
        if bind_type is None:
            continue
        
        for usage in usages:
            caller = usage['func']
            call_addr = usage['call_addr']
            
            # The first arg (r3) to store_args is a pointer to the local bind buffer.
            # In the decompiled code this is typically &local_XX.
            # Find the variable at that stack location by scanning backward
            # from the call to find the addi rN,r1,<offset> that sets r3.
            scan = addr(call_addr)
            bind_buf_offset = None
            for back in range(10):
                try:
                    scan = scan.add(-4)
                except:
                    break
                prev = listing.getInstructionAt(scan)
                if prev is None:
                    continue
                mn = prev.getMnemonicString()
                if mn == 'addi':
                    # Check if destination is r3 and source is r1 (stack)
                    try:
                        dst_reg = prev.getRegister(0)
                        src_reg = prev.getRegister(1)
                        if (dst_reg and src_reg and 
                            dst_reg.getName() == 'r3' and src_reg.getName() == 'r1'):
                            imm = prev.getScalar(2)
                            if imm is not None:
                                bind_buf_offset = int(imm.getValue())
                                break
                    except:
                        pass
            
            if bind_buf_offset is not None:
                # Find and retype the variable at this stack offset
                # The stack offset in Ghidra is negative, addi offset is positive
                # from the frame. We need to convert.
                try:
                    for var in caller.getAllVariables():
                        if not var.isStackVariable():
                            continue
                        vo = var.getStackOffset()
                        # The addi gives the offset from r1 (stack pointer)
                        # Ghidra's stack offset for locals is negative.
                        # The actual mapping depends on frame size.
                        # Just check if the variable name suggests it's the bind buffer
                        var_name = var.getName()
                        dt = var.getDataType()
                        if dt and dt.getName().startswith('boost_function_'):
                            # This is the boost::function struct, the bind buffer
                            # is at a higher stack offset (more negative)
                            # Look for adjacent untyped locals
                            bf_offset = var.getStackOffset()
                            bf_size = dt.getLength()
                            
                            # The bind buffer is typically right above (more negative)
                            # the boost::function struct on the stack
                            pass
                except:
                    pass
    
    print("  Call overrides set:    %d" % overrides_set)
    print("  Equates set:          %d" % equates_set)
    print("  Locals renamed:       %d" % locals_renamed)

    # ── Step 10: Annotate vtables and assignment sites ──────────────
    print("\n[10/10] Annotating vtables and assignment sites...")
    ann_vtables = 0
    ann_sites = 0

    for vt_info in all_vtables:
        entry = vt_info['entry']
        vt_addr = vt_info['vtable_addr']
        mgr = vt_info['manager']
        inv = vt_info['invoker_fn']
        inv_name = inv.getName() if inv else 'unknown'

        comment = '\n'.join([
            "boost::function vtable: %s" % entry['short_name'],
            "  manager = %s @ 0x%08x" % (mgr.getName(),
                                          mgr.getEntryPoint().getOffset()),
            "  invoker = %s" % inv_name,
            "  kind    = %s" % entry['bind_kind'],
            "  type    = %s" % entry['demangled'],
            "  mangled = %s" % entry['mangled'],
        ])

        try:
            listing.setComment(addr(vt_addr), CodeUnit.PLATE_COMMENT, comment)
            ann_vtables += 1
        except:
            pass

        # Apply vtable struct at address
        try:
            listing.clearCodeUnits(addr(vt_addr), addr(vt_addr + 7), False)
            listing.createData(addr(vt_addr), entry['vtable_type'])
        except:
            pass

        # Annotate code that references this vtable
        ann_sites += annotate_assignment_sites(vt_addr, entry)

    print("  Annotated %d vtable(s), %d assignment site(s)." % (
        ann_vtables, ann_sites))

    # ── Summary ───────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("  Typeinfo strings:          %d" % len(typeinfo_strings))
    print("  Managers found:            %d" % sum(len(e['managers']) for e in all_entries))
    print("  Functions renamed:         %d (managers + invokers + helpers)" % renamed)
    print("  Vtables found:             %d" % len(all_vtables))
    print("  Types created:             %d" % type_count)
    print("  Vtable annotations:        %d" % ann_vtables)
    print("  Assignment site comments:  %d" % ann_sites)
    print("=" * 72)

    print("\nFull type catalog:")
    for entry in all_entries:
        print("  [%-10s] %-45s" % (entry.get('bind_kind', '?'),
                                    entry['short_name']))
        print("               %s" % entry['demangled'])

    currentProgram.endTransaction(currentTx, True)
    print("\nTransaction committed.")

except Exception as e:
    currentProgram.endTransaction(currentTx, False)
    print("\nERROR: %s" % str(e))
    import traceback
    traceback.print_exc()
    raise