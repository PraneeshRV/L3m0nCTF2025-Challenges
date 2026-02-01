# Jailer Challenge - Challenger Walkthrough

## Initial Analysis

### Step 1: Basic Reconnaissance
```bash
file jailer
# ELF 64-bit LSB pie executable, x86-64, stripped

./jailer
# Usage: ./jailer "command"

./jailer "id"
# uid=1000(user) gid=1000(user)

./jailer "cat /flag.txt"
# cat: /flag.txt: No such file or directory (we're jailed!)

./jailer "ls -la"
# Shows limited directory contents
```

### Step 2: Static Analysis with Ghidra/IDA
1. Open binary in Ghidra
2. Find `main()` and trace execution flow
3. Key functions to identify:
   - `verify_compliance()` - RED HERRING
   - `init_security_token()` - **IMPORTANT**
   - `enter_jail()` - Creates the sandbox

### Step 3: Analyze `init_security_token()`
In decompiled code, you'll see:
```c
int fd = open(flag_path, O_RDONLY);
dup2(fd, target_fd);  // ← FD LEAK!
close(fd);
```

This means:
1. Flag file is opened BEFORE jailing
2. FD is duplicated to a specific number
3. Original FD is closed, but the duplicate remains!

### Step 4: Find the Target FD
Look for `calculate_target_fd()` function:
```c
char seed[10];
seed[0] = 'A' + 9;   // 'J'
seed[1] = '0' + 4;   // '4'
seed[2] = '0' + 1;   // '1'
seed[3] = 'a' + 11;  // 'l'
seed[4] = 'A' + 1;   // 'B'
seed[5] = 'a' + 17;  // 'r'
seed[6] = '0' + 3;   // '3'
seed[7] = '0' + 4;   // '4'
seed[8] = 'a' + 10;  // 'k'
// Seed = "J41lBr34k"

uint32_t val = 0x1337;
for (i = 0; i < 9; i++) {
    val = ((val << 3) | (val >> 29));  // rotate left
    val ^= seed[i];
    val = (val * 31337) & 0xFFFFFFFF;
}
return (val % 97) + 103;
```

### Step 5: Calculate the FD
Write a script to compute it:
```python
seed = "J41lBr34k"
val = 0x1337

for c in seed:
    val = ((val << 3) | (val >> 29)) & 0xFFFFFFFF
    val ^= ord(c)
    val = (val * 31337) & 0xFFFFFFFF

target_fd = (val % 97) + 103
print(f"Target FD: {target_fd}")
# Output: Target FD: 128
```

### Step 6: Exploit!
```bash
./jailer "cat <&128"
```

**Output:**
```
L3m0nCTF{fd_l34k_thr0ugh_th3_b4rs}
```

## Alternative Discovery Methods

### Method 1: Brute Force FDs
```bash
for fd in $(seq 100 200); do
    result=$(./jailer "cat <&$fd" 2>/dev/null)
    if [ -n "$result" ]; then
        echo "FD $fd: $result"
    fi
done
```

### Method 2: List Open FDs
```bash
./jailer "ls -la /proc/self/fd"
# Look for unusual FD numbers
```

## Key Insights
1. File descriptors persist across chroot/jail
2. If a file is opened BEFORE jailing, the FD is accessible AFTER
3. Look for `dup2()` calls that copy FDs to unusual numbers
4. Common FD leak range: 100-200 (to avoid stdin/stdout/stderr)
