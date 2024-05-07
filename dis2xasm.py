import xdis
import re

# consts
SUFFIX = ".pyasm"
MAIN = "<module>"
# xasm headers
CONSTS = "Constants"
NAMES = "Names"
VARNAMES = "Varnames"
KWARG = "Keyword-only arguments"
POSARGS = "Positional arguments"
FREEVARS = "Free variables"
CELLVARS = "Cell variables"
ASM = "asm"
ARGMAX = "arg_max"
LOCMIN = "loc_min"
UNUSED_CNT = 0
UNUSED = "X"
UNUSED_N = f"|{UNUSED}{{}}|"
UNUSED_C = f"|\"{UNUSED}{{}}\"|"
UNUSED_NRE = rf"\|({UNUSED}" + r"\d+)\|"
UNUSED_CRE = rf"\|(\"{UNUSED}" + r"\d+\")\|"
NONE = "None"
ZERO = "0"
# regex
PTN_CO = r"<code object (.+) at (0x[0-9a-fA-F]+), file \".*\", line \d+>"
PTN_CO_START = PTN_CO + r":\n"
PTN_LNO = r"(?:\n|^)\s*(\d+)\s+\d+ "
PTN_BOFF = r"\n\s+\d+ "
PTN_ARG = r"([A-Z_]+)\s+(\d+)\s+\((.+)\)"
PTN_ARGF = r"([A-Z_]+)\s+(\d+)"
PTN_NAME = r"\w+"

class dis2xasm():
    def __init__(self, _dis_file, _ver):
        self.ver = _ver
        if self.ver >= (3, 10):
            exit(f"[-] XASM not support python version {'.'.join(map(lambda x: str(x), self.ver))}!\n")
        try:
            with open(_dis_file, 'r') as f:
                self.disAsm = f.read()
        except FileNotFoundError:
            exit(f"[-] File {_dis_file} is not exist.\n")
        self.fileName = f"xasm_{_dis_file}"
        self.fileName += SUFFIX if not _dis_file.endswith(SUFFIX) else ""
        self.xAsm = f"# Python bytecode {'.'.join(map(lambda x: str(x), self.ver))}\n\n"
        self.opVer = xdis.__dict__[f"opcode_{''.join([str(x) for x in self.ver])}"]
        self.coAsmMap = {}
        self.funcMap = {}
        self.xrefMap = {}
        self.fvDict = {}
        self.fkwDict = {}
        return

    def _split_asm(self):
        rsltMap = {}
        for x in self.disAsm.split("Disassembly of "):
            reobj = re.match(PTN_CO_START, x)
            if reobj is not None:
                name, addr = reobj.groups()
                asm = x[reobj.end():]
                if name not in rsltMap.keys():
                    rsltMap.update({name: asm})
                else:
                    rsltMap.update({f"{name}_{addr}": asm})
                    self.funcMap.update({addr: (name, f"{name}_{addr}")})
            elif MAIN not in rsltMap.keys():
                rsltMap.update({MAIN: x})
            else:
                exit(f"[-] Bytecode spliting failed.\n")
        return rsltMap

    def _adjust_asm(self, asm):
        def repl(o):
            name, addr = o.groups()
            s = list(o.group())
            if addr in self.funcMap.keys():
                assert name == self.funcMap[addr][0]
                name = self.funcMap[addr][1]
                ib, ie = [t[1]-t[0] for t in zip(o.regs[0], o.regs[1])]
                s[ib:ie] = name
            return ''.join(s)
        newAsm = asm.replace(">>", "  ")
        newAsm = re.sub(PTN_CO, repl, newAsm)
        newAsm = re.sub(PTN_LNO, lambda o: f"\n{o.group(1)}:\n", newAsm)
        newAsm = re.sub(PTN_BOFF, "\n", newAsm)
        return newAsm.strip("\n")

    def _parse_asm(self, asm, curFunc):
        def _dict_upd(d, k, v: list):
            if k not in d.keys():
                d[k] = v
            else:
                d[k] = list(set(d[k] + v))
            return
        newAsm = self._adjust_asm(asm)
        co = {
            CONSTS: {},
            NAMES: {},
            VARNAMES: {},
            POSARGS: -1,
            FREEVARS: {},
            CELLVARS: {},
            ASM: newAsm,
            ARGMAX: -1,
            LOCMIN: None
        }
        fv, fkw = {}, {}
        varState = []
        op = self.opVer
        asm = newAsm.split("\n")
        for i in range(len(asm)):
            reobj = re.search(PTN_ARG, asm[i])
            if reobj is not None:
                opcode, idx, arg = reobj.groups()
                idx = int(idx)
                if op.opmap[opcode] in op.hasconst:
                    co[CONSTS].update({idx: arg})
                elif op.opmap[opcode] in op.hasname:
                    co[NAMES].update({idx: arg})
                elif op.opmap[opcode] in op.haslocal:
                    co[VARNAMES].update({idx: arg})
                    if "STORE" in opcode:
                        varState.append(idx)
                    elif idx not in varState:
                        co[ARGMAX] = max(co[ARGMAX], idx)
                elif op.opmap[opcode] in op.hasfree:
                    co[CELLVARS].update({idx: arg}) # cellvars and freevars
                reobj = re.match(PTN_CO, arg)
                if reobj is not None:
                    _dict_upd(self.xrefMap, curFunc, [reobj.group(1)])
                if opcode == "MAKE_FUNCTION" and (idx & 0x2 or idx & 0x8): # idx -> MAKE_FUNCTION's flags
                    kwCnt = 2 if (idx & 0x2 and idx & 0x4) else (1 if idx & 0x2 else None)
                    cloCnt, kwFlag = None, None
                    func = None
                    for j in range(i)[::-1]:
                        if func is None:
                            reobj = re.search(PTN_CO, asm[j])
                            if reobj is not None:
                                func = reobj.group(1)
                        else:
                            if idx & 0x2: # get keyword arguments - Part 1
                                if kwFlag is None:
                                    reobj = re.search(PTN_ARGF, asm[j])
                                    if reobj is not None and reobj.group(1) == "BUILD_CONST_KEY_MAP":
                                        kwCnt -= 1 if kwCnt > 0 else 0
                                        kwFlag = True if kwCnt == 0 else None
                                elif kwFlag:
                                    kwFlag = False
                                    reobj = re.search(PTN_ARG, asm[j])
                                    assert reobj is not None and reobj.group(1) == "LOAD_CONST"
                                    kwTuple = reobj.group(3)
                                    _dict_upd(fkw, func, re.findall(PTN_NAME, kwTuple))
                            elif idx & 0x8: # get freevar
                                if cloCnt is None:
                                    reobj = re.search(PTN_ARGF, asm[j])
                                    if reobj is not None and reobj.group(1) == "BUILD_TUPLE":
                                        cloCnt = int(reobj.group(2))
                                elif cloCnt > 0:
                                    reobj = re.search(PTN_ARG, asm[j])
                                    if reobj is not None and reobj.group(1) == "LOAD_CLOSURE":
                                        cloCnt -= 1
                                        freevar = reobj.group(3)
                                        _dict_upd(fv, func, [freevar])
            else:
                reobj = re.search(PTN_ARGF, asm[i])
                if reobj is not None and reobj.group(1) == "CALL_FUNCTION_KW": # get keyword arguments - Part 2
                    reobj = re.search(PTN_ARG, asm[i-1])
                    assert reobj is not None and reobj.group(1) == "LOAD_CONST"
                    kwTuple = reobj.group(3)
                    _dict_upd(fkw, func, re.findall(PTN_NAME, kwTuple))
        co[LOCMIN] = min(varState) if varState else -1
        return co, fv, fkw

    def _integrate_asm(self, fn):
        def _sort_dict_idx(s, isConst=False):
            if not co[s]:
                return
            rslt = {}
            d = co[s]
            keys = list(d.keys())
            fullKeys = [x for x in range(max(keys)+1)]
            diff = list(set(fullKeys) - set(keys))
            global UNUSED_CNT
            for x in diff:
                if not isConst:
                    d.update({x: UNUSED_N.format(UNUSED_CNT)})
                    UNUSED_CNT += 1
                elif NONE not in d.values():
                    d.update({x: NONE})
                elif ZERO not in d.values():
                    d.update({x: ZERO})
                else:
                    d.update({x: UNUSED_C.format(UNUSED_CNT)})
                    UNUSED_CNT += 1
            for x in fullKeys:
                rslt.update({x: d[x]})
            co[s] = rslt
            return
        co = self.coAsmMap[fn]
        # adjust consts
        _sort_dict_idx(CONSTS, True)
        # adjust names
        _sort_dict_idx(NAMES)
        # adjust varnames
        _sort_dict_idx(VARNAMES)
        argidx = max(co[ARGMAX], co[LOCMIN] - 1)
        if fn in self.fkwDict.keys():
            for kw in self.fkwDict[fn]:
                if kw not in co[VARNAMES].values():
                    for i in range(argidx+1)[::-1]:
                        if UNUSED in co[VARNAMES][i]:
                            co[VARNAMES][i] = kw
                            break
                    else:
                        print(f"[*] WARNING: Wrong keyword arguments in {fn}.")
        # adjust argcounts
            argidx -= len(self.fkwDict[fn])
        co[POSARGS] = argidx
        # adjust freevars
        if fn in self.fvDict.keys():
            idx_list = [next(k for k, v in co[CELLVARS].items() if v == fv) for fv in self.fvDict[fn]]
            idx = min(idx_list)
            for k, v in list(co[CELLVARS].items()):
                if k >= idx:
                    co[FREEVARS][k-idx] = v
                    del co[CELLVARS][k]
        _sort_dict_idx(FREEVARS)
        # adjust cellvars
        _sort_dict_idx(CELLVARS)
        return

    def _write_asm(self, fn, co):
        def _get_lists(s, isConst=False):
            rslt = ""
            for k, v in co[s].items():
                v = re.sub(UNUSED_NRE, lambda o: o.group(1), v) if not isConst else re.sub(UNUSED_CRE, lambda o: o.group(1), v)
                rslt += f"#  {k}: {v}\n"
            return rslt
        output = f"# Method Name: {fn}\n"
        if co[CONSTS]:
            output += f"# {CONSTS}:\n"
            output += _get_lists(CONSTS, True)
        if co[NAMES]:
            output += f"# {NAMES}:\n"
            output += _get_lists(NAMES)
        if co[VARNAMES]:
            output += f"# {VARNAMES}:\n# "
            varnames = list(co[VARNAMES].values())
            output += re.sub(UNUSED_NRE, lambda o: o.group(1), ", ".join(varnames))
            output += f"\n"
            if fn in self.fkwDict.keys():
                output += f"# {KWARG}: {len(self.fkwDict[fn])}\n"
            if co[POSARGS] >= 0:
                output += f"# {POSARGS}:\n# "
                output += re.sub(UNUSED_NRE, lambda o: o.group(1), ", ".join(varnames[:co[POSARGS]+1]))
                output += f"\n"
        if co[FREEVARS]:
            output += f"# {FREEVARS}:\n"
            output += _get_lists(FREEVARS)
        if co[CELLVARS]:
            output += f"# {CELLVARS}:\n"
            output += _get_lists(CELLVARS)
        output += co[ASM]
        output += "\n\n"
        return output

    def run(self):
        self.coAsmMap = self._split_asm()
        for name, asm in self.coAsmMap.items():
            self.coAsmMap[name], freevars, funcKwargs = self._parse_asm(asm, name)
            self.fvDict.update(freevars)
            self.fkwDict.update(funcKwargs)
        for name in self.coAsmMap.keys():
            self._integrate_asm(name)
        return

    def write(self, fn=None):
        if fn is None:
            fn = self.fileName
        with open(fn, "w") as f:
            funcNotWritten = list(self.coAsmMap.keys())
            while funcNotWritten: # write with new coAsmMap and xrefMap
                name = funcNotWritten.pop(0)
                if name not in self.xrefMap.keys() or not set(funcNotWritten).intersection(set(self.xrefMap[name])):
                    self.xAsm += self._write_asm(name, self.coAsmMap[name])
                else:
                    funcNotWritten.append(name)
            f.write(self.xAsm)
            print(f"[+] {fn} has been written!")

    def xasm2pyc(self):
        from xasm import xasm_cli
        xasm_cli.main([self.fileName])
        return


if __name__ == '__main__':
    import sys
    dx = dis2xasm(sys.argv[1], (3, 8)) # In Python 3.8 performs better than others
    dx.run()
    dx.write() # custom output filename
    dx.xasm2pyc()