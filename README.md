# dis2xasm

Convert Python's `dis` disassembly output to xasm format so that you can use the [xasm](https://github.com/rocky/python-xasm) tool to get the assembly results (in .pyc).

No more worrying about tearing Python bytecode text in CTF! \^0^/

## dependencies

```shell
python3 -m pip install xasm xdis
```

## usage

```shell
python3 dis2xasm.py chal.txt
```

or use it in Python:

```python
>>> from dis2xasm import dis2xasm
>>> dx = dis2xasm("bytecode", (3, 8)) # "bytecode" is the bytecode's filename
>>> dx.run()
>>> dx.write("bytecode.pyasm") # custom output filename
[+] bytecode.pyasm has been written!
>>> dx.xasm2pyc() # use xasm to get .pyc
Wrote Python 3.8 bytecode file "xasm_bytecode.pyc"; 46934 bytes.
```

And then you can use some decompiler like [decompile3](https://github.com/rocky/python-decompile3) or [pycdc](https://github.com/zrax/pycdc) to get its source code.
