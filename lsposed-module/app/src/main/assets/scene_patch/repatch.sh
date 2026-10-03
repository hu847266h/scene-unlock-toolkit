#!/system/bin/sh
# ============================================================
# scene-daemon memory hotpatch - one-shot re-apply script (v4, Alpha10)
# daemon: N1 2026.10 Alpha10 memfd text 0x2B9000
# Changes vs v3: pick LARGEST r-xs memfd (stub + text mappings now),
#                new offsets, SITE3 dropped.
# Usage: su -c "sh /data/local/tmp/scene_patch/repatch.sh"
# Needs: /data/local/tmp/scene_patch/{memfd_patched.bin, mempoke2}
# ============================================================
DIR=/data/local/tmp/scene_patch
IMG=$DIR/memfd_patched.bin
POKE=$DIR/mempoke2
IMGSZ=2854912
OFF_SC=0x2b8938
OFF_S1=0x1e554c
OFF_S2=0x1e3b40

PID=$(pgrep -o scene-daemon)
if [ -z "$PID" ]; then
    echo "[!] scene-daemon not running, start Scene first"
    exit 1
fi

# pick the LARGEST r-xs memfd mapping (v4: stub mapping is small, text is big)
grep -a "memfd" /proc/$PID/maps | grep "r-xs" > "$DIR/.maps"
B=""; BSZ=0
while read -r ADDR REST; do
    S=${ADDR%%-*}; E=${ADDR#*-}
    SZ=$(( 0x$E - 0x$S ))
    if [ "$SZ" -gt "$BSZ" ]; then BSZ=$SZ; B=$S; fi
done < "$DIR/.maps"
rm -f "$DIR/.maps"
if [ -z "$B" ]; then
    echo "[!] memfd code mapping not found"
    exit 1
fi

ENT=$(ls /proc/$PID/map_files/ 2>/dev/null | grep "^$B" | head -1)
if [ -z "$ENT" ]; then
    echo "[!] map_files entry missing (base=$B)"
    exit 1
fi
M="/proc/$PID/map_files/$ENT"
echo "[*] pid=$PID base=0x$B map=$M size=$BSZ"

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
SC=$(awk -v s=$((0x$B)) 'BEGIN{printf "%x", s+'$OFF_SC'}')
A1=$(awk -v s=$((0x$B)) 'BEGIN{printf "%x", s+'$OFF_S1'}')
A2=$(awk -v s=$((0x$B)) 'BEGIN{printf "%x", s+'$OFF_S2'}')

OK=0
for TID in $(ls /proc/$PID/task/); do
    ST=$(awk '{print $3}' /proc/$PID/task/$TID/stat 2>/dev/null)
    echo "[*] try thread $TID (state=$ST) ..."
    if $POKE $TID $SC $A1 $A2 $SC $SC; then
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
ss -tlnp 2>/dev/null | grep -q 14754 && echo "[+] TCP 14754 listening" || echo "[!] 14754 not listening (idle daemon is fine, restart app to wake it)"
exit 0
