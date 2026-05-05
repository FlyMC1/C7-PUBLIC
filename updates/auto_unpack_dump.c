#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

static FILE *g_logf = NULL;

static void log_line(const char *msg) {
    puts(msg);
    if (g_logf) {
        fputs(msg, g_logf);
        fputc('\n', g_logf);
        fflush(g_logf);
    }
}

static void log_printf(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_line(buf);
}

static void show_error_box(const char *title, const char *msg) {
    MessageBoxA(NULL, msg, title, MB_ICONERROR | MB_OK);
}

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

static int wide_to_utf8(const wchar_t *in, char **out) {
    int needed = WideCharToMultiByte(CP_UTF8, 0, in, -1, NULL, 0, NULL, NULL);
    if (needed <= 0) {
        return 0;
    }
    *out = (char *)calloc((size_t)needed, 1);
    if (!*out) {
        return 0;
    }
    return WideCharToMultiByte(CP_UTF8, 0, in, -1, *out, needed, NULL, NULL) > 0;
}

static int build_default_paths(wchar_t **dll_path, wchar_t **out_pe_path, wchar_t **log_path) {
    wchar_t exe_path[MAX_PATH];
    wchar_t *slash;
    size_t base_len;

    DWORD n = GetModuleFileNameW(NULL, exe_path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return 0;
    }

    slash = wcsrchr(exe_path, L'\\');
    if (!slash) {
        return 0;
    }
    *slash = L'\0';
    base_len = wcslen(exe_path);

    *dll_path = (wchar_t *)calloc(base_len + 1 + wcslen(L"snowfall.dll") + 1, sizeof(wchar_t));
    *out_pe_path = (wchar_t *)calloc(base_len + 1 + wcslen(L"snowfall_unpacked_auto.dll") + 1, sizeof(wchar_t));
    *log_path = (wchar_t *)calloc(base_len + 1 + wcslen(L"auto_unpack_dump.log") + 1, sizeof(wchar_t));
    if (!*dll_path || !*out_pe_path || !*log_path) {
        free(*dll_path);
        free(*out_pe_path);
        free(*log_path);
        *dll_path = NULL;
        *out_pe_path = NULL;
        *log_path = NULL;
        return 0;
    }

    swprintf(*dll_path, base_len + 1 + wcslen(L"snowfall.dll") + 1, L"%s\\snowfall.dll", exe_path);
    swprintf(*out_pe_path, base_len + 1 + wcslen(L"snowfall_unpacked_auto.dll") + 1, L"%s\\snowfall_unpacked_auto.dll", exe_path);
    swprintf(*log_path, base_len + 1 + wcslen(L"auto_unpack_dump.log") + 1, L"%s\\auto_unpack_dump.log", exe_path);
    return 1;
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
    DWORD wait_ms = 8000;
    wchar_t *dll_path = NULL;
    wchar_t *out_pe_path = NULL;
    wchar_t *log_path = NULL;
    char *dll_path_u8 = NULL;
    char *out_pe_path_u8 = NULL;

    if (argc >= 3) {
        if (argc >= 4) {
            wait_ms = (DWORD)strtoul(argv[3], NULL, 10);
        }
        if (!utf8_to_wide(argv[1], &dll_path) || !utf8_to_wide(argv[2], &out_pe_path)) {
            show_error_box("auto_unpack_dump", "Failed to parse input paths.");
            free(dll_path);
            free(out_pe_path);
            return 1;
        }

        {
            wchar_t *tmp_dll = NULL;
            wchar_t *tmp_out = NULL;
            if (!build_default_paths(&tmp_dll, &tmp_out, &log_path)) {
                free(tmp_dll);
                free(tmp_out);
                log_path = _wcsdup(L"auto_unpack_dump.log");
            } else {
                free(tmp_dll);
                free(tmp_out);
            }
        }
    } else {
        if (!build_default_paths(&dll_path, &out_pe_path, &log_path)) {
            show_error_box("auto_unpack_dump", "Failed to build default paths from EXE location.");
            return 1;
        }
    }

    if (!wide_to_utf8(dll_path, &dll_path_u8) || !wide_to_utf8(out_pe_path, &out_pe_path_u8)) {
        show_error_box("auto_unpack_dump", "Failed to convert paths for logging.");
        free(dll_path);
        free(out_pe_path);
        free(log_path);
        free(dll_path_u8);
        free(out_pe_path_u8);
        return 1;
    }

    g_logf = _wfopen(log_path ? log_path : L"auto_unpack_dump.log", L"wb");
    log_line("=== auto_unpack_dump start ===");
    log_printf("Input DLL: %s", dll_path_u8);
    log_printf("Output PE: %s", out_pe_path_u8);
    log_printf("Wait(ms): %lu", (unsigned long)wait_ms);

    uint8_t *orig_file = NULL;
    size_t orig_len = 0;
    if (!read_file_all(dll_path, &orig_file, &orig_len) || !is_valid_pe(orig_file, orig_len)) {
        log_line("Failed to read or parse input DLL as PE64.");
        show_error_box("auto_unpack_dump", "Failed to read or parse input DLL as PE64.");
        free(dll_path);
        free(out_pe_path);
        free(log_path);
        free(dll_path_u8);
        free(out_pe_path_u8);
        free(orig_file);
        if (g_logf) {
            fclose(g_logf);
        }
        return 1;
    }

    HMODULE mod = LoadLibraryW(dll_path);
    if (!mod) {
        DWORD err = GetLastError();
        char msg[256];
        log_printf("LoadLibraryW failed with error %lu", (unsigned long)err);
        snprintf(msg, sizeof(msg), "LoadLibraryW failed with error %lu", (unsigned long)err);
        show_error_box("auto_unpack_dump", msg);
        free(dll_path);
        free(out_pe_path);
        free(log_path);
        free(dll_path_u8);
        free(out_pe_path_u8);
        free(orig_file);
        if (g_logf) {
            fclose(g_logf);
        }
        return 1;
    }

    log_printf("Loaded module at %p", (void *)mod);
    log_printf("Waiting %lu ms for runtime unpacking...", (unsigned long)wait_ms);
    Sleep(wait_ms);

    IMAGE_DOS_HEADER *mem_dos = (IMAGE_DOS_HEADER *)mod;
    IMAGE_NT_HEADERS64 *mem_nt = (IMAGE_NT_HEADERS64 *)((uint8_t *)mod + mem_dos->e_lfanew);
    DWORD image_size = mem_nt->OptionalHeader.SizeOfImage;

    uint8_t *rebuilt = (uint8_t *)malloc(orig_len);
    if (!rebuilt) {
        log_line("Out of memory.");
        show_error_box("auto_unpack_dump", "Out of memory.");
        FreeLibrary(mod);
        free(dll_path);
        free(out_pe_path);
        free(log_path);
        free(dll_path_u8);
        free(out_pe_path_u8);
        free(orig_file);
        if (g_logf) {
            fclose(g_logf);
        }
        return 1;
    }
    memcpy(rebuilt, orig_file, orig_len);

    IMAGE_DOS_HEADER *disk_dos = (IMAGE_DOS_HEADER *)rebuilt;
    IMAGE_NT_HEADERS64 *disk_nt = (IMAGE_NT_HEADERS64 *)(rebuilt + disk_dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(disk_nt);

    size_t changed_bytes = 0;
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

        for (DWORD j = 0; j < copy_size; j++) {
            uint8_t newv = *((uint8_t *)mod + va + j);
            if (rebuilt[raw + j] != newv) {
                changed_bytes++;
                rebuilt[raw + j] = newv;
            }
        }
    }

    if (!write_file_all(out_pe_path, rebuilt, orig_len)) {
        log_line("Failed to write output file.");
        show_error_box("auto_unpack_dump", "Failed to write output file.");
        FreeLibrary(mod);
        free(dll_path);
        free(out_pe_path);
        free(log_path);
        free(dll_path_u8);
        free(out_pe_path_u8);
        free(orig_file);
        free(rebuilt);
        if (g_logf) {
            fclose(g_logf);
        }
        return 1;
    }

    log_line("Wrote rebuilt image to output PE path.");
    log_printf("Bytes changed from memory snapshot: %llu", (unsigned long long)changed_bytes);
    if (changed_bytes == 0) {
        log_line("No section bytes changed. Try a longer wait or dynamic debugger-assisted dump.");
        show_error_box("auto_unpack_dump",
            "No section bytes changed. Try wait_ms=20000+ or use x64dbg+Scylla.");
    }
    log_line("Note: IAT/OEP may still need manual fixing in Scylla/x64dbg for best decompilation results.");
    log_line("=== auto_unpack_dump done ===");

    FreeLibrary(mod);
    free(dll_path);
    free(out_pe_path);
    free(log_path);
    free(dll_path_u8);
    free(out_pe_path_u8);
    free(orig_file);
    free(rebuilt);
    if (g_logf) {
        fclose(g_logf);
    }
    return 0;
}
