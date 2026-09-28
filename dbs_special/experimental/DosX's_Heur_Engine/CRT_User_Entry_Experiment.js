/*
 * Archived CRT user-entry discovery prototype for Detect It Easy PE heuristics.
 * This is not a standalone rule and must not be enabled as-is.
 * It depends on PE, PE_Cached, getAsmOpCode(), getOptHeaderOffset(),
 * getFileBackedTlsCallbackAddresses(), readUnsignedQword(),
 * isVirtualAddressRangeMapped(), isVirtualAddressRangeFileBacked(),
 * SECTION_FLAGS_EXECUTE and SECTION_FLAGS_WRITE from the main heuristic.
 * See CRT_User_Entry_Experiment.txt for the safety failure and test record.
 */

/**
 * Resolves one exact IAT slot to its declared import function and library.
 * Descriptor and slot bytes must be file-backed before any derived read.
 *
 * @param {number} slotAddress - Virtual address of an import address table slot.
 * @returns {Object|undefined} Name and Library for that slot, if reliable.
 */
function getEpImportNameAtSlot(slotAddress) {
    var pointerSize = PE_Cached.is64bit ? 8 : 4;
    if (!isVirtualAddressRangeFileBacked(slotAddress, pointerSize, 0)) return undefined;

    var optionalHeaderOffset = getOptHeaderOffset(), optionalHeaderSizeOffset = optionalHeaderOffset - 4;
    if (!isFinite(optionalHeaderOffset) || optionalHeaderOffset !== Math.floor(optionalHeaderOffset) ||
        optionalHeaderSizeOffset < 0 || optionalHeaderSizeOffset + 2 > PE_Cached.fileSize) return undefined;

    var optionalHeaderSize = PE.readWord(optionalHeaderSizeOffset),
        numberOfDirectoriesOffset = optionalHeaderOffset + (PE_Cached.is64bit ? 0x6C : 0x5C),
        directoryOffset = optionalHeaderOffset + (PE_Cached.is64bit ? 0x70 : 0x60) + 8;
    if (directoryOffset + 8 > optionalHeaderOffset + optionalHeaderSize ||
        directoryOffset + 8 > PE_Cached.fileSize || PE.read_uint32(numberOfDirectoriesOffset) < 2) return undefined;

    var importDirectoryRva = PE.read_uint32(directoryOffset);
    if (!importDirectoryRva) return undefined;

    for (var i = 0; i < PE_Cached.numberOfUnmanagedImports && i < 256; i++) {
        var descriptorAddress = PE_Cached.imageBase + importDirectoryRva + i * 20;
        if (!isVirtualAddressRangeFileBacked(descriptorAddress, 20, 0)) return undefined;

        var descriptorOffset = PE.VAToOffset(descriptorAddress);
        if (descriptorOffset < 0 || descriptorOffset + 20 > PE_Cached.fileSize) return undefined;

        var firstThunkRva = PE.read_uint32(descriptorOffset + 16),
            thunkIndex = (slotAddress - PE_Cached.imageBase - firstThunkRva) / pointerSize;
        if (thunkIndex >= 0 && thunkIndex === Math.floor(thunkIndex) && thunkIndex < PE.getNumberOfImportThunks(i)) {
            var libraryName = PE.getImportLibraryName(i);
            if (!libraryName) return undefined;
            var library = libraryName.split(/[\\\/]/).pop().toUpperCase();
            return { Name: PE.getImportFunctionName(i, thunkIndex), Library: library };
        }
    }
    return undefined;
}



/**
 * Decodes the length of non-branching SSE forms unsupported by DiE's x86 decoder.
 * Only XORPS/XORPD and MOVLPS/MOVLPD with a valid ModRM address are accepted;
 * other 0F opcodes must never be treated as harmless padding.
 *
 * @param {number} address - File-backed executable instruction address.
 * @returns {number} Complete instruction length, or zero if unsupported.
 */
function getEpCrtSafeSseLength(address) {
    if (!PE_Cached.isI386 || !isVirtualAddressRangeFileBacked(address, 3, SECTION_FLAGS_EXECUTE)) return 0;

    var offset = PE.VAToOffset(address), prefix = PE.readByte(offset) === 0x66 ? 1 : 0;
    if (!isVirtualAddressRangeFileBacked(address, prefix + 3, SECTION_FLAGS_EXECUTE)) return 0;

    var opcode = PE.readByte(offset + prefix + 1),
        modRm = PE.readByte(offset + prefix + 2),
        mode = modRm >> 6, base = modRm & 7,
        length = prefix + 3;
    if (PE.readByte(offset + prefix) !== 0x0F ||
        (opcode !== 0x57 && opcode !== 0x13) ||
        (opcode === 0x13 && mode === 3)) return 0;

    if (mode !== 3 && base === 4) {
        if (!isVirtualAddressRangeFileBacked(address, length + 1, SECTION_FLAGS_EXECUTE)) return 0;
        var sib = PE.readByte(offset + length);
        length++;
        if (mode === 0 && (sib & 7) === 5) length += 4;
    } else if (mode === 0 && base === 5) {
        length += 4;
    }
    if (mode === 1) length++;
    if (mode === 2) length += 4;

    return length <= 15 && isVirtualAddressRangeFileBacked(address, length, SECTION_FLAGS_EXECUTE) ? length : 0;
}



/**
 * Proves that a recognized CRT cookie initializer returns on every bounded path.
 * Only four returning system queries used by the initializer may cross an IAT call.
 * Unknown calls, indirect transfers, cycles and undecodable bytes fail closed.
 *
 * @param {number} callAddress - Direct CALL from the entry stub.
 * @returns {boolean} Whether all paths through its callee reach a near RET.
 */
function isEpCrtCookieReturnProven(callAddress) {
    var call = PE.getDisasmString(callAddress),
        directCall = call && call.match(/^CALL (0X[0-9A-F]+|\d+)$/);
    if (!directCall) return false;

    var pending = [parseInt(directCall[1], 0)], visited = {}, processed = 0,
        allowedImports = {
            GetSystemTimeAsFileTime: true, GetCurrentProcessId: true,
            GetCurrentThreadId: true, QueryPerformanceCounter: true
        };

    while (pending.length && processed < 128) {
        var address = pending.pop(), key = address.toString();
        if (visited[key]) continue;
        visited[key] = true;

        var instruction = PE.getDisasmString(address), length = PE.getDisasmLength(address),
            opCode = getAsmOpCode(instruction), nextAddress = address + length,
            branch = instruction && instruction.match(/^(J[A-Z]+) (0X[0-9A-F]+|\d+)$/),
            importCall = instruction && instruction.match(/^CALL (?:DWORD|QWORD) PTR \[(0X[0-9A-F]+)\]$/);
        if (opCode === "DB") {
            length = getEpCrtSafeSseLength(address);
            if (!length) return false;
            pending.push(address + length);
            processed++;
            continue;
        }
        if (!opCode || length < 1 || length > 15 ||
            !isVirtualAddressRangeFileBacked(address, length, SECTION_FLAGS_EXECUTE)) return false;
        processed++;

        if (/^RET(?:N)?(?: (?:0X[0-9A-F]+|\d+))?$/.test(instruction)) continue;
        if (branch && opCode !== "JMPF") {
            var branchTarget = parseInt(branch[2], 0);
            if (branchTarget <= address) return false;
            pending.push(branchTarget);
            if (opCode !== "JMP") pending.push(nextAddress);
            continue;
        }
        if (importCall) {
            var imported = getEpImportNameAtSlot(parseInt(importCall[1], 0));
            if (!imported || !allowedImports.hasOwnProperty(imported.Name) ||
                !/^(?:KERNEL32|KERNELBASE)(?:\.DLL)?$/.test(imported.Library)) return false;
        } else if (/^(?:J|CALL|RET|INT|HLT|UD2|IRET|LOOP|SYSCALL|SYSENTER)/.test(opCode)) {
            return false;
        }
        pending.push(nextAddress);
    }

    return pending.length === 0 && processed > 0;
}



/**
 * Rejects a CRT call only when its entire small direct-flow graph cannot return.
 * A returning path, unknown CALL, indirect transfer or exhausted budget is not proof.
 *
 * @param {number} target - Direct CALL destination in CRT startup.
 * @param {number} depth - Bounded direct-call nesting depth.
 * @returns {boolean} Whether the bounded callee has only non-returning paths.
 */
function isEpCrtDirectCallNonreturnProven(target, depth) {
    var pending = [target], visited = {}, processed = 0, hasNonreturnTerminal = false;

    while (pending.length && processed < 64) {
        var address = pending.pop(), key = address.toString();
        if (visited[key]) {
            hasNonreturnTerminal = true;
            continue;
        }
        visited[key] = true;

        var instruction = PE.getDisasmString(address), length = PE.getDisasmLength(address),
            opCode = getAsmOpCode(instruction), nextAddress = address + length,
            branch = instruction && instruction.match(/^(J[A-Z]+) (0X[0-9A-F]+|\d+)$/),
            directCall = instruction && instruction.match(/^CALL (0X[0-9A-F]+|\d+)$/),
            importedExit = instruction && instruction.match(/^(?:CALL|JMP) (?:DWORD|QWORD) PTR \[(0X[0-9A-F]+)\]$/);
        if (!opCode || opCode === "DB" || length < 1 || length > 15 ||
            !isVirtualAddressRangeFileBacked(address, length, SECTION_FLAGS_EXECUTE)) return false;
        processed++;

        if (/^RET(?:N)?(?: (?:0X[0-9A-F]+|\d+))?$/.test(instruction)) return false;
        if (branch && opCode !== "JMPF") {
            pending.push(parseInt(branch[2], 0));
            if (opCode !== "JMP") pending.push(nextAddress);
        } else if (directCall) {
            if (depth >= 2 || !isEpCrtDirectCallNonreturnProven(parseInt(directCall[1], 0), depth + 1)) return false;
            hasNonreturnTerminal = true;
        } else if (importedExit) {
            var imported = getEpImportNameAtSlot(parseInt(importedExit[1], 0));
            if (!imported || imported.Name !== "ExitProcess" ||
                !/^(?:KERNEL32|KERNELBASE)(?:\.DLL)?$/.test(imported.Library)) return false;
            hasNonreturnTerminal = true;
        } else if (/^(?:HLT|UD2|INT3)$/.test(opCode)) {
            hasNonreturnTerminal = true;
        } else if (/^(?:J|CALL|RET|INT|IRET|LOOP|SYSCALL|SYSENTER)/.test(opCode)) {
            return false;
        } else {
            pending.push(nextAddress);
        }
    }

    return pending.length === 0 && hasNonreturnTerminal;
}



/**
 * Locates a console application's user entry in a recognized VC-compatible CRT.
 * This is candidate discovery only: calls inside CRT are assumed to return for
 * traversal, but neither that assumption nor visited instructions create verdicts.
 * Only the CRT startup function is searched; called functions are never entered.
 *
 * @returns {number|undefined} Unique validated user entry, if recognized.
 */
function getEpCrtUserEntryCandidate() {
    if (!PE_Cached.isEntryPointAnalysisAllowed || !PE_Cached.isArchX86 || PE_Cached.isDriver || PE_Cached.isDynamicLinkLibrary) return undefined;

    var crtTlsCallbacks = getFileBackedTlsCallbackAddresses();
    if (!crtTlsCallbacks || crtTlsCallbacks.length) return undefined;

    var entry = PE_Cached.addressOfUnmanagedEntryPoint, startup = undefined,
        first = PE.getDisasmString(entry), firstLength = PE.getDisasmLength(entry);

    if (!first || !firstLength || !isVirtualAddressRangeFileBacked(entry, firstLength, SECTION_FLAGS_EXECUTE)) return undefined;

    if (PE_Cached.is64bit) {
        var allocation = first.match(/^SUB RSP, (0X[0-9A-F]+|\d+)$/);
        if (!allocation || parseInt(allocation[1], 0) > 0x100) return undefined;

        var cookieCallAddress = entry + firstLength, cookieCall = PE.getDisasmString(cookieCallAddress),
            restoreAddress = cookieCallAddress + PE.getDisasmLength(cookieCallAddress),
            restore = PE.getDisasmString(restoreAddress),
            jumpAddress = restoreAddress + PE.getDisasmLength(restoreAddress),
            jump = PE.getDisasmString(jumpAddress);

        if (!/^CALL (?:0X[0-9A-F]+|\d+)$/.test(cookieCall) ||
            restore !== "ADD RSP, " + allocation[1] || !/^JMP (?:0X[0-9A-F]+|\d+)$/.test(jump)) return undefined;
        if (!isEpCrtCookieReturnProven(cookieCallAddress)) return undefined;
        startup = parseInt(jump.substring(4), 0);
    } else {
        var jumpAddress = entry + firstLength, jump = PE.getDisasmString(jumpAddress);
        if (!/^CALL (?:0X[0-9A-F]+|\d+)$/.test(first) ||
            !/^JMP (?:0X[0-9A-F]+|\d+)$/.test(jump)) return undefined;
        if (!isEpCrtCookieReturnProven(entry)) return undefined;
        startup = parseInt(jump.substring(4), 0);
    }

    if (!isVirtualAddressRangeFileBacked(startup, 1, SECTION_FLAGS_EXECUTE)) return undefined;

    var pending = [startup], nextIndex = 0, visited = {}, visitedCount = 0,
        instructions = {}, lengths = {}, previous = {}, calls = [];
    while (nextIndex < pending.length && nextIndex < 2048 && visitedCount < 512) {
        var address = pending[nextIndex++], key = address.toString();
        if (visited[key] || !isVirtualAddressRangeFileBacked(address, 1, SECTION_FLAGS_EXECUTE)) continue;
        visited[key] = true;
        visitedCount++;

        var instruction = PE.getDisasmString(address), length = PE.getDisasmLength(address),
            opCode = getAsmOpCode(instruction), nextAddress = address + length,
            directCall = instruction && instruction.match(/^CALL (0X[0-9A-F]+|\d+)$/),
            directBranch = instruction && instruction.match(/^(J[A-Z]+) (0X[0-9A-F]+|\d+)$/);

        if (!opCode || opCode === "DB" || length < 1 || length > 15 ||
            !isVirtualAddressRangeFileBacked(address, length, SECTION_FLAGS_EXECUTE)) continue;
        instructions[key] = instruction;
        lengths[key] = length;

        if (directCall) calls.push({ Address: address, Target: parseInt(directCall[1], 0), Next: nextAddress });
        if (directBranch && opCode !== "JMPF") {
            pending.push(parseInt(directBranch[2], 0));
            if (opCode === "JMP") continue;
        } else if (/^(?:RET|RETN|RETF|HLT|INT|INT3|UD2|IRET|JMP|JMPF)$/.test(opCode)) {
            continue;
        }
        if (!previous.hasOwnProperty(nextAddress)) previous[nextAddress] = address;
        pending.push(nextAddress);
    }
    if (nextIndex < pending.length) return undefined;

    var candidate = undefined, candidateCallAddress = -1;
    for (var i = 0; i < calls.length; i++) {
        var call = calls[i], history = [], cursor = call.Address;
        for (var p = 0; p < 8 && previous.hasOwnProperty(cursor); p++) {
            var prior = previous[cursor];
            if (prior + lengths[prior] !== cursor) break;
            history.unshift(instructions[prior]);
            cursor = prior;
        }
        if (history.length !== 8 || !isVirtualAddressRangeFileBacked(call.Target, 1, SECTION_FLAGS_EXECUTE)) continue;

        var argcGetter = history[4].match(/^CALL (0X[0-9A-F]+|\d+)$/),
            argvGetter = history[2].match(/^CALL (0X[0-9A-F]+|\d+)$/),
            envGetter = history[0].match(/^CALL (0X[0-9A-F]+|\d+)$/);
        if (!argcGetter || !argvGetter || !envGetter) continue;

        var handoff = false, after = PE.getDisasmString(call.Next);
        if (PE_Cached.is64bit) {
            var argvMove = history[6].match(/^MOV RDX, (R(?:AX|BX|CX|DX|SI|DI|BP|8|9|1[0-5]))$/),
                envMove = history[5].match(/^MOV R8, (R(?:AX|BX|CX|DX|SI|DI|BP|8|9|1[0-5]))$/);
            handoff = !!argvMove && !!envMove && history[7] === "MOV ECX, DWORD PTR [RAX]" &&
                history[3] === "MOV " + argvMove[1] + ", QWORD PTR [RAX]" &&
                history[1] === "MOV " + envMove[1] + ", RAX" &&
                /^MOV (?:E(?:BX|SI|DI|BP)|R(?:8|9|1[0-5])D), EAX$/.test(after);
        } else {
            var argvPush = history[6].match(/^PUSH (E(?:AX|BX|CX|DX|SI|DI|BP))$/),
                envPush = history[5].match(/^PUSH (E(?:AX|BX|CX|DX|SI|DI|BP))$/),
                cleanupAddress = call.Next + PE.getDisasmLength(call.Next);
            handoff = !!argvPush && !!envPush && history[7] === "PUSH DWORD PTR [EAX]" &&
                history[3] === "MOV " + argvPush[1] + ", DWORD PTR [EAX]" &&
                history[1] === "MOV " + envPush[1] + ", EAX" &&
                /^ADD ESP, (?:0XC|12)$/.test(after) &&
                /^MOV (?:E(?:BX|SI|DI|BP)), EAX$/.test(PE.getDisasmString(cleanupAddress));
        }
        if (!handoff) continue;

        var getterAddresses = [parseInt(argcGetter[1], 0), parseInt(argvGetter[1], 0)], storage = [];
        for (var g = 0; g < getterAddresses.length; g++) {
            var getterAddress = getterAddresses[g], getter = PE.getDisasmString(getterAddress),
                getterLength = PE.getDisasmLength(getterAddress), storageAddress = undefined;
            if (!getter || getterLength < 1 || getterLength > 15 ||
                !isVirtualAddressRangeFileBacked(getterAddress, getterLength, SECTION_FLAGS_EXECUTE)) break;

            var importJump = getter.match(/^JMP (?:DWORD|QWORD) PTR \[(0X[0-9A-F]+)\]$/);
            if (!importJump && !/^RET(?:N)?$/.test(PE.getDisasmString(getterAddress + getterLength))) break;
            if (PE_Cached.is64bit) {
                var addressLoad = getter.match(/^LEA RAX, \[RIP ([+-]) (0X[0-9A-F]+|\d+)\]$/);
                if (addressLoad) storageAddress = getterAddress + getterLength +
                    parseInt(addressLoad[2], 0) * (addressLoad[1] === "-" ? -1 : 1);
                else {
                    addressLoad = getter.match(/^LEA RAX, \[(0X[0-9A-F]+|\d+)\]$/);
                    if (addressLoad) storageAddress = parseInt(addressLoad[1], 0);
                }
            } else {
                var addressLoad = getter.match(/^MOV EAX, (0X[0-9A-F]+|\d+)$/);
                if (addressLoad) storageAddress = parseInt(addressLoad[1], 0);
            }
            var imported = importJump && getEpImportNameAtSlot(parseInt(importJump[1], 0));
            if (importJump) {
                if (!imported || imported.Name !== (g === 0 ? "__p___argc" : "__p___argv") ||
                    !/^(?:UCRTBASE|MSVCRT|API-MS-WIN-CRT-RUNTIME-L1-1-0)(?:\.DLL)?$/.test(imported.Library)) break;
                storageAddress = parseInt(importJump[1], 0);
                if (!isVirtualAddressRangeFileBacked(storageAddress, PE_Cached.is64bit ? 8 : 4, 0)) break;
            } else if (!isVirtualAddressRangeMapped(storageAddress, PE_Cached.is64bit ? 8 : 4, SECTION_FLAGS_WRITE)) break;
            storage.push(storageAddress);
        }
        if (storage.length !== 2 || storage[0] === storage[1]) continue;
        if (candidate !== undefined) return undefined;
        candidate = call.Target;
        candidateCallAddress = call.Address;
    }

    if (candidate === undefined) return undefined;

    for (var i = 0; i < calls.length; i++) {
        if (calls[i].Address < candidateCallAddress &&
            isEpCrtDirectCallNonreturnProven(calls[i].Target, 0)) return undefined;
    }

    // The CRT may invoke user code from initializer tables before main. Recognize
    // only table layouts with no extra user callback; unfamiliar layouts fail closed.
    var initializerRanges = [], pointerSize = PE_Cached.is64bit ? 8 : 4;
    for (var i = 0; i < calls.length; i++) {
        var tableCall = calls[i];
        if (tableCall.Address >= candidateCallAddress) continue;

        var startMoveAddress = previous[tableCall.Address],
            endMoveAddress = previous[startMoveAddress],
            startMove = instructions[startMoveAddress], endMove = instructions[endMoveAddress],
            tableStart = undefined, tableEnd = undefined;

        if (PE_Cached.is64bit) {
            var startMatch = startMove && startMove.match(/^LEA RCX, \[(0X[0-9A-F]+)\]$/),
                endMatch = endMove && endMove.match(/^LEA RDX, \[(0X[0-9A-F]+)\]$/);
        } else {
            var startMatch = startMove && startMove.match(/^PUSH (0X[0-9A-F]+|\d+)$/),
                endMatch = endMove && endMove.match(/^PUSH (0X[0-9A-F]+|\d+)$/);
        }

        if (!startMatch || !endMatch) continue;

        tableStart = parseInt(startMatch[1], 0);
        tableEnd = parseInt(endMatch[1], 0);
        if (tableEnd <= tableStart || (tableEnd - tableStart) % pointerSize !== 0 ||
            tableEnd - tableStart > 7 * pointerSize ||
            !isVirtualAddressRangeFileBacked(tableStart, tableEnd - tableStart, 0)) continue;
        initializerRanges.push({ Address: tableCall.Address, Start: tableStart, End: tableEnd });
    }
    initializerRanges.sort(function (a, b) { return a.Address - b.Address; });
    if (initializerRanges.length < 2) return undefined;

    var xiRange = initializerRanges[initializerRanges.length - 2],
        xcRange = initializerRanges[initializerRanges.length - 1],
        xiCount = (xiRange.End - xiRange.Start) / pointerSize,
        xcCount = (xcRange.End - xcRange.Start) / pointerSize;

    if ((xiCount !== 3 && xiCount !== 7) || xcCount !== 2) return undefined;

    for (var i = 0; i < 2; i++) {
        var range = i === 0 ? xiRange : xcRange;
        for (var address = range.Start; address < range.End; address += pointerSize) {
            var offset = PE.VAToOffset(address),
                callback = PE_Cached.is64bit ? readUnsignedQword(offset) : PE.read_uint32(offset);

            if (callback !== 0 && !isVirtualAddressRangeFileBacked(callback, 1, SECTION_FLAGS_EXECUTE)) return undefined;
        }
    }

    return candidate;
}


/*
 * Former integration point in scanForObfuscations_Native():
 *
 *     var epPolymorphismRootAddress =
 *         getEpCrtUserEntryCandidate() || PE_Cached.addressOfUnmanagedEntryPoint;
 *
 * The shared CFG worklist and epBitstreamStartAddresses were seeded with this
 * root. Its near-entry distance checks also used epPolymorphismRootAddress.
 * A synthetic EP transfer was added only if the root remained the declared EP.
 *
 * Do not restore that one-root integration. A nonzero TLS callback or a nonzero
 * C++ initializer may execute user code before main(). The prototype verifies
 * only that callback pointers are file-backed, not that they are CRT-only.
 */
