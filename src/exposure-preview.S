/* 3.2-cn 实验候选；只由 0x362084 的取景 AE 调用点进入。
 * 不接管积分时间/增益驱动。M 档的曝光偏差（十分之一 EV）
 * 注入原取景补偿字段；原 AE 的时间/增益限幅继续执行。
 * cache 的物理闭环、AF/闪光副作用仍需真机验证。
 * JSON 为实际补丁字节，本文件供审阅，不是独立可链接程序。
 */
.syntax unified
.arm
/* 放在 0x369d68，原死代码已核对顺序入口不可达及静态引用。 */
preview_wrapper:
    push {r4, lr}
    mov r4, r0
    bl 0x361ad4             /* 完整执行原配置填充器 */
    push {r0-r3, ip}
    mrs r3, cpsr
    ldr r0, [r4, #8]       /* AE 内部模式，1=M */
    cmp r0, #1
    bne restore
    ldr r0, [r4, #4]       /* 只对原算法 kind=0 生效 */
    cmp r0, #0
    bne restore
    ldr ip, meter_cache
    ldr r0, [ip]
    cmp r0, #50
    movgt r0, #50
    cmn r0, #50
    mvnlt r0, #49          /* -50 */
    str r0, [r4, #0x30]    /* 原曝光补偿表：10单位=1EV */
restore:
    msr cpsr_f, r3
    pop {r0-r3, ip}
    pop {r4, pc}
meter_cache:
    .word 0xc150f9f4
