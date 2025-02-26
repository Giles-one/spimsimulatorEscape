.data
msg:   .asciiz "proof of concept of **WRITE_SYSCALL** and **READ_SYSCALL**   memory overflow\n"

.text
.globl main
main:   
        li  $v0, 4
        la  $a0, msg
        syscall          # print message

        li  $v0, 14      # READ_SYSCALL
        li  $a0, 0       # stdin
        lui $a1, 0x7fff
        ori $a1, 0xfffc  # set A2 0x7ffffffc (0x80000000 - 4)
        li  $a2, 0x8     # set A1 8          (0x80000000 + 4)
        syscall          # read(0, 0x80000000-4, 8)
        