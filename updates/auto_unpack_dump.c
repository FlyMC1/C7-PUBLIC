#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static int utf8_to_wide(const char *in, wchar_t **out) {
    int needed = MultiByteToWideChar(CP_UTF8, 0, in, -1, NULL, 0);
    if (needed <= 0) {
        return 0;
    }
    *out = (wchar_t *)calloc((size_t)needed, sizeof(wchar_t));
    if (!*out) {
        return 0;
    }
    return MultiByteToWideChar(CP_UTF8, 0, in, -1, *out, needed) > 0;
}

static int read_file_all(const wchar_t *path, uint8_t **buf, size_t *len) {
    FILE *f = _wfopen(path, L"rb");
    if (!f) {
        return 0;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }
    long sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return 0;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    *buf = (uint8_t *)malloc((size_t)sz);
    if (!*buf) {
        fclose(f);
        return 0;
    }

    size_t got = fread(*buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(*buf);
        *buf = NULL;
        return 0;
    }

    *len = (size_t)sz;
    return 1;
}

static int write_file_all(const wchar_t *path, const uint8_t *buf, size_t len) {
    FILE *f = _wfopen(path, L"wb");
    if (!f) {
        return 0;
    }
    size_t wrote = fwrite(buf, 1, len, f);
    fclose(f);
    return wrote == len;
}

static int is_valid_pe(const uint8_t *buf, size_t len) {
    if (len < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > len) {
        return 0;
    }
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
            "Usage: %s <dll_path> <output_pe> [wait_ms]\n"
            "Example: %s C:\\\\samples\\\\snowfall.dll C:\\\\samples\\\\snowfall_unpacked_auto.dll 8000\n",
            argv[0], argv[0]);
        return 1;
    }

    DWORD wait_ms = 8000;
    if (argc >= 4) {
        wait_ms = (DWORD)strtoul(argv[3], NULL, 10);
    }

    wchar_t *dll_path = NULL;
    wchar_t *out_pe_path = NULL;
    if (!utf8_to_wide(argv[1], &dll_path) || !utf8_to_wide(argv[2], &out_pe_path)) {
        fprintf(stderr, "Failed to parse input paths.\n");
        free(dll_path);
        free(out_pe_path);
        return 1;
    }

    uint8_t *orig_file = NULL;
    size_t orig_len = 0;
    if (!read_file_all(dll_path, &orig_file, &orig_len) || !is_valid_pe(orig_file, orig_len)) {
        fprintf(stderr, "Failed to read or parse input DLL as PE64.\n");
        free(dll_path);
        free(out_pe_path);
        free(orig_file);
        return 1;
    }

    HMODULE mod = LoadLibraryW(dll_path);
    if (!mod) {
        fprintf(stderr, "LoadLibraryW failed with error %lu\n", GetLastError());
        free(dll_path);
        free(out_pe_path);
        free(orig_file);
        return 1;
    }

    printf("Loaded module at %p\n", (void *)mod);
    printf("Waiting %lu ms for runtime unpacking...\n", (unsigned long)wait_ms);
    Sleep(wait_ms);

    IMAGE_DOS_HEADER *mem_dos = (IMAGE_DOS_HEADER *)mod;
    IMAGE_NT_HEADERS64 *mem_nt = (IMAGE_NT_HEADERS64 *)((uint8_t *)mod + mem_dos->e_lfanew);
    DWORD image_size = mem_nt->OptionalHeader.SizeOfImage;

    uint8_t *rebuilt = (uint8_t *)malloc(orig_len);
    if (!rebuilt) {
        fprintf(stderr, "Out of memory.\n");
        FreeLibrary(mod);
        free(dll_path);
        free(out_pe_path);
        free(orig_file);
        return 1;
    }
    memcpy(rebuilt, orig_file, orig_len);

    IMAGE_DOS_HEADER *disk_dos = (IMAGE_DOS_HEADER *)rebuilt;
    IMAGE_NT_HEADERS64 *disk_nt = (IMAGE_NT_HEADERS64 *)(rebuilt + disk_dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(disk_nt);

    for (WORD i = 0; i < disk_nt->FileHeader.NumberOfSections; i++) {
        DWORD va = sec[i].VirtualAddress;
        DWORD raw = sec[i].PointerToRawData;
        DWORD raw_size = sec[i].SizeOfRawData;
        DWORD vsize = sec[i].Misc.VirtualSize;
        DWORD copy_size = raw_size < vsize ? raw_size : vsize;

        if (raw == 0 || copy_size == 0) {
            continue;
        }
        if ((size_t)raw + copy_size > orig_len) {
            continue;
        }
        if ((size_t)va + copy_size > image_size) {
            continue;
        }

        memcpy(rebuilt + raw, (uint8_t *)mod + va, copy_size);
    }

    if (!write_file_all(out_pe_path, rebuilt, orig_len)) {
        fprintf(stderr, "Failed to write output file.\n");
        FreeLibrary(mod);
        free(dll_path);
        free(out_pe_path);
        free(orig_file);
        free(rebuilt);
        return 1;
    }

    printf("Wrote rebuilt image to output PE path.\n");
    printf("Note: IAT/OEP may still need manual fixing in Scylla/x64dbg for best decompilation results.\n");

    FreeLibrary(mod);
    free(dll_path);
    free(out_pe_path);
    free(orig_file);
    free(rebuilt);
    return 0;
}
