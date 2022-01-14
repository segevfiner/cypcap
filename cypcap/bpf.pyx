# cython: language_level=3str, binding=True
"""
BPF Constants and utility functions.
"""

from . cimport cbpf


def CLASS(code: int) -> int:
    """Get instruction class."""
    return cbpf.BPF_CLASS(code)


LD = cbpf.BPF_LD
LDX = cbpf.BPF_LDX
ST = cbpf.BPF_ST
STX = cbpf.BPF_STX
ALU = cbpf.BPF_ALU
JMP = cbpf.BPF_JMP
RET = cbpf.BPF_RET
MISC = cbpf.BPF_MISC


def SIZE(code: int) -> int:
    """Get ld/ldx size."""
    return cbpf.BPF_SIZE(code)


W = cbpf.BPF_W
H = cbpf.BPF_H
B = cbpf.BPF_B


def MODE(code: int) -> int:
    """Get ld/ldx mode."""
    return cbpf.BPF_MODE(code)


IMM = cbpf.BPF_IMM
ABS = cbpf.BPF_ABS
IND = cbpf.BPF_IND
MEM = cbpf.BPF_MEM
LEN = cbpf.BPF_LEN
MSH = cbpf.BPF_MSH


def OP(code: int) -> int:
    """Get alu/jmp op."""
    return cbpf.BPF_OP(code)


ADD = cbpf.BPF_ADD
SUB = cbpf.BPF_SUB
MUL = cbpf.BPF_MUL
DIV = cbpf.BPF_DIV
OR = cbpf.BPF_OR
AND = cbpf.BPF_AND
LSH = cbpf.BPF_LSH
RSH = cbpf.BPF_RSH
NEG = cbpf.BPF_NEG
MOD = cbpf.BPF_MOD
XOR = cbpf.BPF_XOR
JA = cbpf.BPF_JA
JEQ = cbpf.BPF_JEQ
JGT = cbpf.BPF_JGT
JGE = cbpf.BPF_JGE
JSET = cbpf.BPF_JSET


def SRC(code: int) -> int:
    """Get alu/jmp src."""
    return cbpf.BPF_SRC(code)


K = cbpf.BPF_K
X = cbpf.BPF_X


def RVAL(code: int) -> int:
    """Get return value src."""
    return cbpf.BPF_RVAL(code)


A = cbpf.BPF_A


def MISCOP(code: int) -> int:
    """Get misc op."""
    return cbpf.BPF_MISCOP(code)


TAX = cbpf.BPF_TAX
TXA = cbpf.BPF_TXA


def STMT(code, k):
    """Create a BPF statement instruction tuple."""
    return (code, 0, 0, k)


def JUMP(code, jt, jf, k):
    """Create a BPF jump instruction tuple."""
    return (code, jt, jf, k)


MEMWORDS = cbpf.BPF_MEMWORDS
