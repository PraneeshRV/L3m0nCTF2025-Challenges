/*
 * jailer (FD Leak Challenge)
 * Flag: L3m0nCTF{fd_l34k_thr0ugh_th3_b4rs} (in flag.txt)
 * Vulnerability: File descriptor 128 leaks the flag
 * 
 * For local testing: uses ./flag.txt
 * For Docker: change to /flag.txt
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

/* RED HERRING - fake compliance check */
int verify_compliance(void)
{
    FILE *f = fopen("/etc/passwd", "r");
    if (f) {
        fclose(f);
        return 1;
    }
    return 1;
}

/* Complex FD calculation algorithm */
__attribute__((noinline))
int calculate_target_fd()
{
    /* Seed: "J41lBr34k" built with arithmetic */
    volatile char seed[10];
    seed[0] = 'A' + 9;   /* J */
    seed[1] = '0' + 4;   /* 4 */
    seed[2] = '0' + 1;   /* 1 */
    seed[3] = 'a' + 11;  /* l */
    seed[4] = 'A' + 1;   /* B */
    seed[5] = 'a' + 17;  /* r */
    seed[6] = '0' + 3;   /* 3 */
    seed[7] = '0' + 4;   /* 4 */
    seed[8] = 'a' + 10;  /* k */
    seed[9] = '\0';

    /* Multi-stage hash */
    uint32_t val = 0x1337;
    for (int i = 0; i < 9; i++)
    {
        val = ((val << 3) | (val >> 29));
        val ^= (unsigned char)seed[i];
        val = (val * 31337) & 0xFFFFFFFF;
    }

    return (val % 97) + 103;  /* Results in FD 128 */
}

/* VULNERABILITY: Opens flag, leaks FD */
__attribute__((noinline))
int init_security_token()
{
    /* Use local path for testing, /flag.txt for Docker */
    const char *flag_path = "flag.txt";
    
    int target_fd = calculate_target_fd();
    
    int fd = open(flag_path, O_RDONLY);
    if (fd < 0) {
        /* Try absolute path as fallback */
        fd = open("/flag.txt", O_RDONLY);
        if (fd < 0)
            return -1;
    }

    dup2(fd, target_fd);
    close(fd);
    return 0;
}

/* Enter jail (simplified - works without root) */
int enter_jail()
{
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s \"command\"\n", argv[0]);
        return 1;
    }

    verify_compliance();

    if (init_security_token() != 0)
    {
        fprintf(stderr, "Security init failed.\n");
        return 1;
    }

    enter_jail();

    return system(argv[1]);
}
