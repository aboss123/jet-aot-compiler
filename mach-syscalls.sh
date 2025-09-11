# Dump all BSD/Mach syscall macros from the macOS SDK headers
SDK="/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"
HDR="$SDK/usr/include/sys/syscall.h"
awk '/^[[:space:]]*#define[[:space:]]+SYS_[A-Za-z0-9_]+[[:space:]]+[0-9]+/{
  gsub(/^#define[[:space:]]+SYS_/,""); split($0,a); printf "%-6s %s\n", a[2], a[1]
}' "$HDR" | sort -n

# (Optional) Also list Mach trap numbers (IPC layer)
awk '/^#define[[:space:]]+MACH_.+ [0-9]+/ {print}' "$SDK/usr/include/mach/mach_traps.h" 2>/dev/null
