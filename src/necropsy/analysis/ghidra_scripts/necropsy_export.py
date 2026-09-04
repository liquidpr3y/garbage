# Necropsy function exporter, run by Ghidra headless as a post-script.
#
# Deliberately written in the subset of Python that is valid under both Jython 2.7
# (how Ghidra 10.x-11.x runs .py GhidraScripts today) and CPython 3 (how PyGhidra
# will run them). No f-strings, no print statement, explicit encoding on write.
# Jython is deprecated upstream, so this file is the whole migration surface.
#
# Usage (set by necropsy.analysis.ghidra):
#   analyzeHeadless <proj> <name> -import <file> \
#       -scriptPath <this dir> -postScript necropsy_export.py <out.json> <max_functions>
#
# Read-only: it decompiles and reports. It never runs the sample.
# @category Necropsy

import json

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

DECOMPILE_TIMEOUT_S = 30


def _program_meta(program):
    manager = program.getFunctionManager()
    return {
        "name": program.getName(),
        "language": str(program.getLanguageID()),
        "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": str(program.getImageBase()),
        "executable_format": program.getExecutableFormat(),
        "executable_sha256": program.getExecutableSHA256(),
        # getFunctionCount() includes external (imported) functions, which
        # getFunctions(True) does not iterate. Report both so "exported 1 of 4"
        # is not read as a truncated export.
        "function_count_all": manager.getFunctionCount(),
        "external_function_count": manager.getExternalFunctions().hasNext()
        and sum(1 for _ in manager.getExternalFunctions())
        or 0,
    }


def _called_names(function, limit=24):
    names = []
    try:
        for callee in function.getCalledFunctions(ConsoleTaskMonitor()):
            names.append(callee.getName())
            if len(names) >= limit:
                break
    except Exception:
        pass
    return names


def _decompile_all(program, max_functions):
    iface = DecompInterface()
    options = DecompileOptions()
    iface.setOptions(options)
    iface.openProgram(program)
    monitor = ConsoleTaskMonitor()

    out = []
    manager = program.getFunctionManager()

    # Count what we will actually iterate, so "truncated" means we stopped
    # early rather than "the program also has imports".
    internal_total = 0
    for _ in manager.getFunctions(True):
        internal_total += 1
    truncated = internal_total > max_functions

    count = 0
    for function in manager.getFunctions(True):
        if count >= max_functions:
            break
        count += 1

        entry = {
            "name": function.getName(),
            "address": str(function.getEntryPoint()),
            "size": int(function.getBody().getNumAddresses()),
            "is_thunk": bool(function.isThunk()),
            "is_external": bool(function.isExternal()),
            "calling_convention": str(function.getCallingConventionName()),
            "parameter_count": int(function.getParameterCount()),
            "calls": _called_names(function),
            "decompiled": None,
            "decompile_error": None,
        }

        # Thunks decompile to a single jump; the text is noise and the volume is
        # large in any real binary.
        if not function.isThunk() and not function.isExternal():
            try:
                results = iface.decompileFunction(function, DECOMPILE_TIMEOUT_S, monitor)
                if results is not None and results.decompileCompleted():
                    entry["decompiled"] = results.getDecompiledFunction().getC()
                else:
                    entry["decompile_error"] = (
                        results.getErrorMessage() if results is not None else "no result"
                    )
            except Exception as exc:
                entry["decompile_error"] = str(exc)

        out.append(entry)

    iface.dispose()
    return out, truncated, internal_total


def run():
    args = getScriptArgs()  # noqa: F821 - injected by GhidraScript
    if not args:
        raise ValueError("necropsy_export.py requires an output path argument")
    out_path = args[0]
    max_functions = int(args[1]) if len(args) > 1 else 4000

    program = currentProgram  # noqa: F821 - injected by GhidraScript
    functions, truncated, total = _decompile_all(program, max_functions)

    payload = {
        "schema": 1,
        "program": _program_meta(program),
        "functions": functions,
        "exported": len(functions),
        "total_functions": total,
        "truncated": truncated,
    }


    handle = open(out_path, "wb")
    try:
        handle.write(json.dumps(payload, ensure_ascii=True).encode("utf-8"))
    finally:
        handle.close()

    print("necropsy_export: wrote " + str(len(functions)) + " functions to " + out_path)


run()
