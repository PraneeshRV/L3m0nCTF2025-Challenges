#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <zip.h>

// ============== MAGIC MARKER FOR KEY DERIVATION ==============
__attribute__((section(".magic")))
__attribute__((aligned(8192)))  // At offset 0x2000
const char magic_marker[16] = "OUROBOROS_KEY";

// ============== DYNAMIC KEY DERIVATION ==============
static uint8_t derive_flag_key() {
    uint8_t buffer[16];
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return 0x42;
    
    lseek(fd, 0x4000, SEEK_SET);  // Magic section at 0x4000
    ssize_t n = read(fd, buffer, 16);
    close(fd);
    
    if (n < 16) return 0x42;
    
    uint8_t key = 0;
    for (int i = 0; i < 16; i++) {
        key ^= buffer[i];
    }
    
    return key;
}

// ============== EXPLOIT VERIFICATION ==============
static int verify_exploit_success() {
    struct stat sb;
    
    if (lstat("sandbox/escape", &sb) != 0) return 0;
    if (!S_ISLNK(sb.st_mode)) return 0;
    
    char target[256];
    ssize_t len = readlink("sandbox/escape", target, sizeof(target)-1);
    if (len <= 0) return 0;
    target[len] = '\0';
    
    if (strcmp(target, "/") != 0 && strcmp(target, "../..") != 0) {
        return 0;
    }
    
    if (access("pwned", F_OK) == 0 || access("/tmp/pwned", F_OK) == 0) {
        return 1;
    }
    
    return 0;
}

// ============== FLAG PRINTING ==============
static void maybe_print_flag() {
    if (!verify_exploit_success()) {
        printf("[*] Extraction complete.\n");
        return;
    }
    
    // Derive key
    uint8_t key = derive_flag_key();
    

    
    unsigned char encoded_flag[] = {
        0x00, 0x7f, 0x21, 0x7c, 0x22, 0x0f, 0x18, 0x0a, 0x37, 0x3f, 0x35,
        0x21, 0x2e, 0x7c, 0x20, 0x7d, 0x2f, 0x13, 0x20, 0x7d, 0x22, 0x27,
        0x13, 0x7f, 0x3f, 0x2f, 0x78, 0x3c, 0x7f, 0x13, 0x21, 0x78, 0x3f,
        0x38, 0x7f, 0x3e, 0x31, 0x00
    };
    
    printf("\n[!] ═══════════════════════════════════════\n");
    printf("[!] EXPLOIT SUCCESSFUL!\n");
    printf("[!] ═══════════════════════════════════════\n\n");
    printf("[+] Flag: ");
    
    // Use explicit length since first decoded byte might be 0
    size_t flag_len = sizeof(encoded_flag) - 1;  // -1 for null terminator
    for (size_t i = 0; i < flag_len; i++) {
        printf("%c", encoded_flag[i] ^ key);
    }
    printf("\n\n");
}

//============== VULNERABLE PATH SANITIZER ==============
static int sanitize_path(const char *path) {
    if (strncmp(path, "sandbox/", 8) != 0) {
        printf("[!] Path validation failed: %s\n", path);
        return 0;
    }
    return 1;
}

// ============== FILE EXTRACTION ==============
static void extract_symlink(const char *filename, const char *target) {
    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "sandbox/%s", filename);
    
    if (!sanitize_path(fullpath)) return;
    
    if (symlink(target, fullpath) == 0) {
        printf("[+] Created symlink: %s -> %s\n", filename, target);
    }
}

static void extract_file(const char *filename, const uint8_t *data, size_t len) {
    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "sandbox/%s", filename);
    
    if (!sanitize_path(fullpath)) return;
    
    char *last_slash = strrchr(fullpath, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(fullpath, 0755);
        *last_slash = '/';
    }
    
    int fd = open(fullpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, data, len);
        close(fd);
        printf("[+] Extracted: %s (%zu bytes)\n", filename, len);
    }
}

// ============== ZIP PROCESSING WITH LIBZIP ==============
static void process_zip(const char *zipfile) {
    int err;
    zip_t *za = zip_open(zipfile, ZIP_RDONLY, &err);
    
    if (!za) {
        zip_error_t error;
        zip_error_init_with_code(&error, err);
        printf("[!] Error: Cannot open ZIP: %s\n", zip_error_strerror(&error));
        zip_error_fini(&error);
        return;
    }
    
    zip_int64_t num_entries = zip_get_num_entries(za, 0);
    printf("[*] Processing ZIP file (%lld entries)...\n", (long long)num_entries);
    printf("[*] Extracting to sandbox/\n");
    
    for (zip_int64_t i = 0; i < num_entries; i++) {
        zip_stat_t stat;
        zip_stat_index(za, i, 0, &stat);
        
        const char *name = stat.name;
        zip_uint8_t opsys;
        zip_uint32_t attributes;
        
        if (zip_file_get_external_attributes(za, i, 0, &opsys, &attributes) != 0) {
            continue;
        }
        
        int is_symlink = (opsys == ZIP_OPSYS_UNIX) && 
                         (((attributes >> 16) & 0xF000) == 0xA000);
        
        if (is_symlink) {
            zip_file_t *zf = zip_fopen_index(za, i, 0);
            if (zf) {
                char target[256];
                zip_int64_t len = zip_fread(zf, target, sizeof(target) - 1);
                if (len > 0) {
                    target[len] = '\0';
                    extract_symlink(name, target);
                }
                zip_fclose(zf);
            }
        } else {
            zip_file_t *zf = zip_fopen_index(za, i, 0);
            if (zf) {
                uint8_t *buffer = malloc(stat.size);
                if (buffer) {
                    zip_fread(zf, buffer, stat.size);
                    extract_file(name, buffer, stat.size);
                    free(buffer);
                }
                zip_fclose(zf);
            }
        }
    }
    
    zip_close(za);
}

// ============== MAIN ==============
int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <zipfile>\n", argv[0]);
        return 1;
    }
    
    if (mkdir("sandbox", 0755) != 0 && errno != EEXIST) {
        printf("[!] Warning: Failed to create sandbox: %s\n", strerror(errno));
    }
    
    process_zip(argv[1]);
    maybe_print_flag();
    
    return 0;
}
