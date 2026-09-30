#!/system/bin/sh
# ============================================================
# scene-daemon memory hotpatch - one-shot re-apply script (v3)
# Re-apply patch after scene-daemon restart (reboot / app update).
# Usage: su -c "sh /data/local/tmp/scene_patch/repatch.sh"
# Needs: /data/local/tmp/scene_patch/{memfd_patched.bin, mempoke2}
# ============================================================
DIR=/data/local/tmp/scene_patch
IMG=$DIR/memfd_patched.bin
POKE=$DIR/mempoke2
# memfd code segment size (0x2AD000)
IMGSZ=2805760
# patch offsets inside memfd
OFF_SC=0x2acf00    # shellcode slot (48-byte 4-addr icache flusher)
OFF_S1=0x1e562c    # SITE1: b.le -> nop   (Function A license branch)
OFF_S2=0x1ee6e4    # SITE2: b.gt -> b     (Function B force success path)
OFF_S3=0x1ee6ec    # ADD imm: #0x4b4(expired) -> #0x4ad(invalid)

PID=$(pgrep -o scene-daemon)
if [ -z "$PID" ]; then
    echo "[!] scene-daemon not running, start Scene first"
    exit 1
fi

LINE=$(grep -a "memfd:upx" /proc/$PID/maps | grep "r-xs" | head -1)
if [ -z "$LINE" ]; then
    echo "[!] memfd code mapping not found"
    exit 1
fi
B=$(echo "$LINE" | cut -d- -f1)

ENT=$(ls /proc/$PID/map_files/ 2>/dev/null | grep "^$B" | head -1)
if [ -z "$ENT" ]; then
    echo "[!] map_files entry missing (base=$B)"
    exit 1
fi
M="/proc/$PID/map_files/$ENT"
echo "[*] pid=$PID base=0x$B map=$M"

# 1) version safety check, then full overwrite with patched image
cat "$M" > "$DIR/.cur.bin" 2>/dev/null
CURSZ=$(wc -c < "$DIR/.cur.bin" 2>/dev/null)
if [ "$CURSZ" != "$IMGSZ" ]; then
    echo "[!] memfd size unexpected ($CURSZ), abort"
    rm -f "$DIR/.cur.bin"
    exit 1
fi
DIFF=$(cmp -l "$DIR/.cur.bin" $IMG 2>/dev/null | wc -l)
rm -f "$DIR/.cur.bin"
if [ "$DIFF" -gt 400 ]; then
    echo "[!] daemon code differs from patch baseline by $DIFF bytes (>400),"
    echo "    Scene probably updated its daemon, abort to avoid corruption"
    exit 2
fi
dd if=$IMG of="$M" bs=4096 conv=notrunc 2>/dev/null
echo "[*] baseline check ok (diff=$DIFF), image written ($IMGSZ bytes)"

# 2) per-thread ptrace injection: run icache flush shellcode
#    (main thread may be stuck in a syscall where PC patching is useless;
#     try every thread until one reports x4==0)
SC=$(awk -v s=$((0x$B)) 'BEGIN{printf "%x", s+0x2acf00}')
A1=$(awk -v s=$((0x$B)) 'BEGIN{printf "%x", s+0x1e562c}')
A2=$(awk -v s=$((0x$B)) 'BEGIN{printf "%x", s+0x1ee6e4}')
A3=$(awk -v s=$((0x$B)) 'BEGIN{printf "%x", s+0x1ee6ec}')

OK=0
for TID in $(ls /proc/$PID/task/); do
    ST=$(awk '{print $3}' /proc/$PID/task/$TID/stat 2>/dev/null)
    echo "[*] try thread $TID (state=$ST) ..."
    if $POKE $TID $SC $A1 $A2 $A3 $SC; then
        OK=1
        echo "[+] thread $TID injected ok"
        break
    fi
    kill -CONT $TID 2>/dev/null
    sleep 0.3
done

kill -CONT $PID 2>/dev/null

if [ $OK -eq 1 ]; then
    echo "[+] patch applied (icache flushed)"
else
    echo "[!] all thread injections failed"
    exit 3
fi

# 3) sanity check on listen port
ss -tlnp | grep -q 14754 && echo "[+] TCP 14754 listening" || echo "[!] 14754 not listening (idle daemon is fine, restart app to wake it)"
exit 0
