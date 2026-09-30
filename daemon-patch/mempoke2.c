/*
 * mempoke2 — ARM64 进程内 shellcode 执行器 (用于 icache 同步)
 *
 * 原理:
 *   对已写补丁但 icache 未同步的进程, 通过 PTRACE_ATTACH 选一个
 *   当前 PC 位于目标代码段内 (空闲循环) 的线程, SETREGS 把 PC 指向
 *   预先写入代码段空白区的 shellcode (dc cvau + ic ivau + dsb + isb),
 *   PTRACE_CONT 执行后再恢复寄存器现场。
 *
 * usage: mempoke2 <pid> <sc_hex> <a1_hex> <a2_hex> <a3_hex> <a4_hex> <code_lo_hex> <code_hi_hex>
 *   sc       : shellcode 入口地址
 *   a1..a4   : 需要 icache 失效的地址 (x0..x3)
 *   code_lo/hi : 目标代码段范围, 用于挑选 PC 在段内的线程
 *
 * 成功标志: shellcode 末尾 mov x4, xzr; b .  → 轮询到 x4==0 即完成
 * exit 0 = 成功
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

struct user_regs {
    unsigned long long regs[31]; /* x0..x30 */
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};

#define NT_PRSTATUS 1
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205

static int getregs(pid_t pid, struct user_regs *r) {
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
}
static int setregs(pid_t pid, struct user_regs *r) {
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
}
static int wait_stop(pid_t pid) {
    int st;
    if (waitpid(pid, &st, __WALL) == -1) return -1;
    return 0;
}

/* 在单个线程上执行 shellcode; 返回 0 成功 (x4==0) */
static int run_on_thread(pid_t tid, unsigned long sc, unsigned long *a,
                         unsigned long lo, unsigned long hi) {
    if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) return -1;
    if (wait_stop(tid) == -1) return -1;

    struct user_regs orig, mod;
    if (getregs(tid, &orig) == -1) { ptrace(PTRACE_DETACH, tid, NULL, NULL); return -1; }
    if (orig.pc < lo || orig.pc >= hi) {
        /* 该线程不在代码段内, 交给上层重试/换线程 */
        ptrace(PTRACE_DETACH, tid, NULL, NULL);
        return -2;
    }
    fprintf(stderr, "[t%d] pc=%llx (in code range) -> running shellcode @%lx\n",
            tid, orig.pc, sc);

    mod = orig;
    for (int i = 0; i < 4; i++) mod.regs[i] = a[i];
    mod.pc = sc;
    if (setregs(tid, &mod) == -1) { ptrace(PTRACE_DETACH, tid, NULL, NULL); return -1; }

    /* 轮询: CONT 一段时间后 SIGSTOP 检查 x4, 最多 8 次 */
    struct timespec ts = { 0, 150 * 1000 * 1000 };
    struct user_regs now;
    int ok = 0;
    for (int round = 0; round < 8; round++) {
        if (ptrace(PTRACE_CONT, tid, NULL, NULL) == -1) break;
        nanosleep(&ts, NULL);
        kill(tid, SIGSTOP);
        if (wait_stop(tid) == -1) break;
        if (getregs(tid, &now) == -1) break;
        fprintf(stderr, "[t%d] round %d: pc=%llx x4=%llx\n",
                tid, round, now.pc, now.regs[4]);
        if (now.regs[4] == 0 && now.pc >= sc && now.pc < sc + 64) { ok = 1; break; }
        /* 未执行到 shellcode (线程阻塞在 syscall), 恢复后再试 */
    }

    setregs(tid, &orig);   /* 恢复现场, 尽力而为 */
    ptrace(PTRACE_DETACH, tid, NULL, NULL);
    kill(tid, SIGCONT);    /* 防 group-stop 残留 */
    return ok ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc != 7 && argc != 9) {
        fprintf(stderr, "usage: %s pid sc a1 a2 a3 a4 [code_lo code_hi]\n", argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    unsigned long sc = strtoul(argv[2], NULL, 16);
    unsigned long a[4];
    for (int i = 0; i < 4; i++) a[i] = strtoul(argv[3 + i], NULL, 16);
    unsigned long lo = 0, hi = ~0UL;   /* 默认不按 PC 过滤 */
    if (argc == 9) {
        lo = strtoul(argv[7], NULL, 16);
        hi = strtoul(argv[8], NULL, 16);
    }

    /* 枚举线程 */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *d = opendir(path);
    if (!d) { fprintf(stderr, "opendir %s: %s\n", path, strerror(errno)); return 1; }

    pid_t tids[256]; int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) && n < 256) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        tids[n++] = (pid_t)atoi(e->d_name);
    }
    closedir(d);
    fprintf(stderr, "threads: %d\n", n);

    int rc = -1;
    /* 优先挑 PC 在代码段内的线程; 失败则逐个重试 */
    for (int pass = 0; pass < 2 && rc != 0; pass++) {
        for (int i = 0; i < n && rc != 0; i++) {
            rc = run_on_thread(tids[i], sc, a, pass == 0 ? lo : 0, pass == 0 ? hi : ~0UL);
            if (rc == -2) continue;  /* pc 不在段内, 下一个 */
        }
        if (rc != 0) fprintf(stderr, "pass %d failed, retrying without pc filter\n", pass);
    }
    if (rc == 0) { fprintf(stderr, "SHELLCODE DONE, icache synced\n"); return 0; }
    fprintf(stderr, "all threads exhausted\n");
    return 3;
}
