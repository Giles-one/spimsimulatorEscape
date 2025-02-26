.data
msg:   .asciiz "proof of concept of **READ_STRING_SYSCALL** memory overflow\n"

.text
.globl main
main:   
        li  $v0, 4
        la  $a0, msg
        syscall          # print message

        li  $v0, 8       # READ_STRING_SYSCALL
        lui $a0, 0x7fff
        ori $a0, 0xfffc  # set A0 0x7ffffffc (0x80000000 - 4)
        li  $a1, 0x8     # set A1 8
        syscall          # read_input(0x80000000-4, 8)
        