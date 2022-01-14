cypcap.bpf module
-----------------

.. automodule:: cypcap.bpf

   **Instruction classes:**

   .. autofunction:: CLASS

   .. autodata:: LD
   .. autodata:: LDX
   .. autodata:: ST
   .. autodata:: STX
   .. autodata:: ALU
   .. autodata:: JMP
   .. autodata:: RET
   .. autodata:: MISC

   **ld/ldx fields:**

   .. autofunction:: SIZE

   .. autodata:: W
   .. autodata:: H
   .. autodata:: B

   .. autofunction:: MODE

   .. autodata:: IMM
   .. autodata:: ABS
   .. autodata:: IND
   .. autodata:: MEM
   .. autodata:: LEN
   .. autodata:: MSH

   **alu/jmp fields:**

   .. autofunction:: OP

   .. autodata:: ADD
   .. autodata:: SUB
   .. autodata:: MUL
   .. autodata:: DIV
   .. autodata:: OR
   .. autodata:: AND
   .. autodata:: LSH
   .. autodata:: RSH
   .. autodata:: NEG
   .. autodata:: MOD
   .. autodata:: XOR
   .. autodata:: JA
   .. autodata:: JEQ
   .. autodata:: JGT
   .. autodata:: JGE
   .. autodata:: JSET

   .. autofunction:: SRC

   .. autodata:: K
   .. autodata:: X

   **ret - BPF_K and BPF_X also apply:**

   .. autofunction:: RVAL

   .. autodata:: A

   **misc:**

   .. autofunction:: MISCOP

   .. autodata:: TAX
   .. autodata:: TXA

   **utils:**

   .. autofunction:: STMT

   .. autofunction:: JUMP

   .. autodata:: MEMWORDS

      Number of scratch memory words (for BPF_LD|BPF_MEM and BPF_ST).
