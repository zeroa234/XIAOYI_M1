/* Experimental M-only time-preview wrapper.
 * Hook: 0x365684 (original bl 0x35b35c) -> wrapper at 0x369d68.
 * Only scales the time argument when ctrl+0x4c == 1 (M) and
 * 0xc150f9f4 (tenths EV) != 0.  The original time driver call is
 * always executed; return value is preserved.
 */
.syntax unified
.arm
.text
.global preview_time_wrapper
.type preview_time_wrapper, %function
preview_time_wrapper:
    push {r4, lr}
    sub sp, sp, #4          /* padding keeps 8-byte alignment without shifting saved args */
    push {r0-r3, ip}

    ldr r3, =0xc1469694
    ldrb r3, [r3, #0x4c]       /* current AE mode; 1 = M */
    cmp r3, #1
    bne .Loriginal

    ldr r3, =0xc150f9f4
    ldr r3, [r3]               /* tenths EV cache (physical units unproven) */
    cmp r3, #0
    beq .Loriginal

    ldr r0, [sp]               /* original time argument */
    mov r1, r3                 /* compensation in tenths EV */
    bl 0x35d254                /* original scale/target helper */
    mov r1, #0
    bl 0x35b35c                /* original time driver */
    b .Ldone

.Loriginal:
    ldr r0, [sp]
    ldr r1, [sp, #4]           /* original r1 (normally 0) */
    bl 0x35b35c

.Ldone:
    str r0, [sp]               /* return value replaces saved r0 */
    pop {r0-r3, ip}
    add sp, sp, #4
    pop {r4, pc}
.size preview_time_wrapper, .-preview_time_wrapper
.ltorg
