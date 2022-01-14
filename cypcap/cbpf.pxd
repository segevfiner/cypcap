cdef extern from "<pcap.h>":
    pass

cdef extern from "<pcap/bpf.h>":
    unsigned short BPF_CLASS(unsigned short code)

    enum:
        BPF_LD
        BPF_LDX
        BPF_ST
        BPF_STX
        BPF_ALU
        BPF_JMP
        BPF_RET
        BPF_MISC

    unsigned short BPF_SIZE(unsigned short code)

    enum:
        BPF_W
        BPF_H
        BPF_B

    unsigned short BPF_MODE(unsigned short code)

    enum:
        BPF_IMM
        BPF_ABS
        BPF_IND
        BPF_MEM
        BPF_LEN
        BPF_MSH

    unsigned short BPF_OP(unsigned short code)

    enum:
        BPF_ADD
        BPF_SUB
        BPF_MUL
        BPF_DIV
        BPF_OR
        BPF_AND
        BPF_LSH
        BPF_RSH
        BPF_NEG
        BPF_MOD
        BPF_XOR
        BPF_JA
        BPF_JEQ
        BPF_JGT
        BPF_JGE
        BPF_JSET

    unsigned short BPF_SRC(unsigned short code)

    enum:
        BPF_K
        BPF_X

    unsigned short BPF_RVAL(unsigned short code)

    enum:
        BPF_A

    unsigned short BPF_MISCOP(unsigned short code)

    enum:
        BPF_TAX
        BPF_TXA

    enum:
        BPF_MEMWORDS
