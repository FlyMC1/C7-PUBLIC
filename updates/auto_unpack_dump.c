#include <windows.h>
#include <commdlg.h>
#include <tlhelp32.h>
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

static wchar_t *dup_wstr(const wchar_t *src) {
    size_t len = wcslen(src) + 1;
    wchar_t *dst = (wchar_t *)calloc(len, sizeof(wchar_t));
    if (!dst) {
        return NULL;
    }
    memcpy(dst, src, len * sizeof(wchar_t));
    return dst;
}

static int file_exists(const wchar_t *path) {
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
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

static int apply_cwd_fallback_if_needed(wchar_t **dll_path, wchar_t **out_pe_path, wchar_t **log_path) {
    wchar_t cwd[MAX_PATH];
    wchar_t *new_dll = NULL;
    wchar_t *new_out = NULL;
    wchar_t *new_log = NULL;
    size_t base_len;

    if (*dll_path && file_exists(*dll_path)) {
        return 1;
    }

    if (GetCurrentDirectoryW(MAX_PATH, cwd) == 0) {
        return 0;
    }
    base_len = wcslen(cwd);

    new_dll = (wchar_t *)calloc(base_len + 1 + wcslen(L"snowfall.dll") + 1, sizeof(wchar_t));
    new_out = (wchar_t *)calloc(base_len + 1 + wcslen(L"snowfall_unpacked_auto.dll") + 1, sizeof(wchar_t));
    new_log = (wchar_t *)calloc(base_len + 1 + wcslen(L"auto_unpack_dump.log") + 1, sizeof(wchar_t));
    if (!new_dll || !new_out || !new_log) {
        free(new_dll);
        free(new_out);
        free(new_log);
        return 0;
    }

    swprintf(new_dll, base_len + 1 + wcslen(L"snowfall.dll") + 1, L"%s\\snowfall.dll", cwd);
    swprintf(new_out, base_len + 1 + wcslen(L"snowfall_unpacked_auto.dll") + 1, L"%s\\snowfall_unpacked_auto.dll", cwd);
    swprintf(new_log, base_len + 1 + wcslen(L"auto_unpack_dump.log") + 1, L"%s\\auto_unpack_dump.log", cwd);

    if (!file_exists(new_dll)) {
        free(new_dll);
        free(new_out);
        free(new_log);
        return 0;
    }

    free(*dll_path);
    free(*out_pe_path);
    free(*log_path);
    *dll_path = new_dll;
    *out_pe_path = new_out;
    *log_path = new_log;
    return 1;
}

static int prompt_for_dll_path(wchar_t **dll_path, wchar_t **out_pe_path, wchar_t **log_path) {
    OPENFILENAMEW ofn;
    wchar_t selected[MAX_PATH] = {0};
    wchar_t dir[MAX_PATH] = {0};
    wchar_t *slash;
    size_t base_len;
    wchar_t *new_out = NULL;
    wchar_t *new_log = NULL;
    static const wchar_t filter[] = L"DLL Files\0*.dll\0All Files\0*.*\0\0";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = selected;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Select DLL to load and dump";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) {
        return 0;
    }

    wcsncpy(dir, selected, MAX_PATH - 1);
    slash = wcsrchr(dir, L'\\');
    if (!slash) {
        return 0;
    }
    *slash = L'\0';
    base_len = wcslen(dir);

    new_out = (wchar_t *)calloc(base_len + 1 + wcslen(L"snowfall_unpacked_auto.dll") + 1, sizeof(wchar_t));
    new_log = (wchar_t *)calloc(base_len + 1 + wcslen(L"auto_unpack_dump.log") + 1, sizeof(wchar_t));
    if (!new_out || !new_log) {
        free(new_out);
        free(new_log);
        return 0;
    }

    swprintf(new_out, base_len + 1 + wcslen(L"snowfall_unpacked_auto.dll") + 1, L"%s\\snowfall_unpacked_auto.dll", dir);
    swprintf(new_log, base_len + 1 + wcslen(L"auto_unpack_dump.log") + 1, L"%s\\auto_unpack_dump.log", dir);

    free(*dll_path);
    free(*out_pe_path);
    free(*log_path);
    *dll_path = dup_wstr(selected);
    *out_pe_path = new_out;
    *log_path = new_log;
    return *dll_path != NULL;
}

static int read_file_all(const wchar_t *path, uint8_t **buf, size_t *len) {
    FILE *f = _wfopen(path, L"rb");
    long size;
    size_t got;

    if (!f) {
        return 0;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }
    size = ftell(f);
    if (size <= 0) {
        fclose(f);
        return 0;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    *buf = (uint8_t *)malloc((size_t)size);
    if (!*buf) {
        fclose(f);
        return 0;
    }

    got = fread(*buf, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) {
        free(*buf);
        *buf = NULL;
        return 0;
    }

    *len = (size_t)size;
    return 1;
}

static int write_file_all(const wchar_t *path, const uint8_t *buf, size_t len) {
    FILE *f = _wfopen(path, L"wb");
    size_t wrote;
    if (!f) {
        return 0;
    }
    wrote = fwrite(buf, 1, len, f);
    fclose(f);
    return wrote == len;
}

static const char *validate_pe64(const uint8_t *buf, size_t len) {
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;

    if (len < sizeof(IMAGE_DOS_HEADER)) {
        return "file is too small to contain a PE header";
    }
    dos = (const IMAGE_DOS_HEADER *)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return "file does not start with an MZ header";
    }
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > len) {
        return "PE header offset is invalid";
    }
    nt = (const IMAGE_NT_HEADERS64 *)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return "file does not contain a PE signature";
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return "file is not a 64-bit PE image";
    }
    return NULL;
}

static int get_remote_module_base(DWORD pid, const wchar_t *dll_path, uintptr_t *base_out) {
    HANDLE snap;
    MODULEENTRY32W me;
    wchar_t dll_name[MAX_PATH];
    const wchar_t *slash;

    slash = wcsrchr(dll_path, L'\\');
    if (slash) {
        wcsncpy(dll_name, slash + 1, MAX_PATH - 1);
        dll_name[MAX_PATH - 1] = L'\0';
    } else {
        wcsncpy(dll_name, dll_path, MAX_PATH - 1);
        dll_name[MAX_PATH - 1] = L'\0';
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me)) {
        CloseHandle(snap);
        return 0;
    }

    do {
        if (_wcsicmp(me.szExePath, dll_path) == 0 || _wcsicmp(me.szModule, dll_name) == 0) {
            *base_out = (uintptr_t)me.modBaseAddr;
            CloseHandle(snap);
            return 1;
        }
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);
    return 0;
}

static int dump_remote_module(HANDLE process, uintptr_t remote_base, const uint8_t *orig_file, size_t orig_len, const wchar_t *out_path, size_t *changed_out) {
    uint8_t *rebuilt;
    IMAGE_DOS_HEADER *disk_dos;
    IMAGE_NT_HEADERS64 *disk_nt;
    IMAGE_SECTION_HEADER *sec;
    IMAGE_DOS_HEADER mem_dos;
    IMAGE_NT_HEADERS64 mem_nt;
    SIZE_T got;
    size_t changed = 0;
    WORD i;

    if (!ReadProcessMemory(process, (LPCVOID)remote_base, &mem_dos, sizeof(mem_dos), &got) || got != sizeof(mem_dos)) {
        return 0;
    }
    if (!ReadProcessMemory(process, (LPCVOID)(remote_base + (uintptr_t)mem_dos.e_lfanew), &mem_nt, sizeof(mem_nt), &got) || got != sizeof(mem_nt)) {
        return 0;
    }

    rebuilt = (uint8_t *)malloc(orig_len);
    if (!rebuilt) {
        return 0;
    }
    memcpy(rebuilt, orig_file, orig_len);

    disk_dos = (IMAGE_DOS_HEADER *)rebuilt;
    disk_nt = (IMAGE_NT_HEADERS64 *)(rebuilt + disk_dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(disk_nt);

    for (i = 0; i < disk_nt->FileHeader.NumberOfSections; i++) {
        DWORD raw = sec[i].PointerToRawData;
        DWORD raw_size = sec[i].SizeOfRawData;
        DWORD va = sec[i].VirtualAddress;
        DWORD vsize = sec[i].Misc.VirtualSize;
        DWORD copy_size = raw_size < vsize ? raw_size : vsize;
        SIZE_T bytes_read = 0;
        uint8_t *tmp;
        DWORD j;

        if (raw == 0 || copy_size == 0) {
            continue;
        }
        if ((size_t)raw + copy_size > orig_len) {
            continue;
        }
        if ((SIZE_T)va + copy_size > mem_nt.OptionalHeader.SizeOfImage) {
            continue;
        }

        tmp = (uint8_t *)malloc(copy_size);
        if (!tmp) {
            free(rebuilt);
            return 0;
        }
        if (!ReadProcessMemory(process, (LPCVOID)(remote_base + va), tmp, copy_size, &bytes_read) || bytes_read != copy_size) {
            free(tmp);
            free(rebuilt);
            return 0;
        }

        for (j = 0; j < copy_size; j++) {
            if (rebuilt[raw + j] != tmp[j]) {
                rebuilt[raw + j] = tmp[j];
                changed++;
            }
        }
        free(tmp);
    }

    if (!write_file_all(out_path, rebuilt, orig_len)) {
        free(rebuilt);
        return 0;
    }

    free(rebuilt);
    *changed_out = changed;
    return 1;
}

static int run_worker(const wchar_t *dll_path, DWORD hold_ms) {
    HMODULE mod;
    mod = LoadLibraryW(dll_path);
    if (!mod) {
        return (int)GetLastError();
    }
    Sleep(hold_ms);
    FreeLibrary(mod);
    return 0;
}

static int run_controller(const wchar_t *exe_path, const wchar_t *dll_path, const wchar_t *out_path, DWORD wait_ms) {
    uint8_t *orig_file = NULL;
    size_t orig_len = 0;
    const char *pe_error;
    wchar_t command[4096];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    uintptr_t remote_base = 0;
    DWORD start = GetTickCount();
    DWORD exit_code = STILL_ACTIVE;
    HANDLE process = NULL;
    size_t changed_bytes = 0;
    char *dll_u8 = NULL;
    char *out_u8 = NULL;

    if (!wide_to_utf8(dll_path, &dll_u8) || !wide_to_utf8(out_path, &out_u8)) {
        free(dll_u8);
        free(out_u8);
        return 1;
    }

    log_printf("Input DLL: %s", dll_u8);
    log_printf("Output PE: %s", out_u8);
    log_printf("Wait(ms): %lu", (unsigned long)wait_ms);

    if (!file_exists(dll_path)) {
        char msg[1024];
        log_line("Input DLL was not found.");
        snprintf(msg, sizeof(msg), "Input DLL was not found at:\n%s", dll_u8);
        show_error_box("auto_unpack_dump", msg);
        free(dll_u8);
        free(out_u8);
        return 1;
    }

    if (!read_file_all(dll_path, &orig_file, &orig_len)) {
        char msg[1024];
        log_line("Failed to read input DLL from disk.");
        snprintf(msg, sizeof(msg), "Failed to read input DLL from disk:\n%s", dll_u8);
        show_error_box("auto_unpack_dump", msg);
        free(dll_u8);
        free(out_u8);
        return 1;
    }

    pe_error = validate_pe64(orig_file, orig_len);
    if (pe_error) {
        char msg[1024];
        log_printf("Input file is not a supported PE64 image: %s", pe_error);
        snprintf(msg, sizeof(msg), "Input file is not a supported PE64 image:\n%s\n\nPath:\n%s", pe_error, dll_u8);
        show_error_box("auto_unpack_dump", msg);
        free(orig_file);
        free(dll_u8);
        free(out_u8);
        return 1;
    }

    swprintf(command, sizeof(command) / sizeof(command[0]), L"\"%s\" --worker \"%s\" %lu", exe_path, dll_path, (unsigned long)(wait_ms + 30000));
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessW(exe_path, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        char msg[256];
        DWORD err = GetLastError();
        log_printf("CreateProcessW failed with error %lu", (unsigned long)err);
        snprintf(msg, sizeof(msg), "CreateProcessW failed with error %lu", (unsigned long)err);
        show_error_box("auto_unpack_dump", msg);
        free(orig_file);
        free(dll_u8);
        free(out_u8);
        return 1;
    }

    CloseHandle(pi.hThread);
    process = pi.hProcess;
    log_printf("Worker PID: %lu", (unsigned long)pi.dwProcessId);

    while (GetTickCount() - start < wait_ms + 5000) {
        if (get_remote_module_base(pi.dwProcessId, dll_path, &remote_base)) {
            break;
        }
        if (!GetExitCodeProcess(process, &exit_code) || exit_code != STILL_ACTIVE) {
            break;
        }
        Sleep(200);
    }

    if (remote_base == 0) {
        char msg[256];
        GetExitCodeProcess(process, &exit_code);
        if (exit_code == STILL_ACTIVE) {
            log_line("Worker never exposed the DLL as a loaded module.");
            snprintf(msg, sizeof(msg), "Worker did not load the DLL within %lu ms", (unsigned long)(wait_ms + 5000));
        } else {
            log_printf("Worker exited before module enumeration, exit code %lu", (unsigned long)exit_code);
            snprintf(msg, sizeof(msg), "Worker exited before dump. Exit code: %lu", (unsigned long)exit_code);
        }
        show_error_box("auto_unpack_dump", msg);
        TerminateProcess(process, 1);
        CloseHandle(process);
        free(orig_file);
        free(dll_u8);
        free(out_u8);
        return 1;
    }

    log_printf("Remote module base: 0x%p", (void *)remote_base);
    Sleep(wait_ms);

    if (!dump_remote_module(process, remote_base, orig_file, orig_len, out_path, &changed_bytes)) {
        show_error_box("auto_unpack_dump", "Failed to read the DLL image from the worker process.");
        TerminateProcess(process, 1);
        CloseHandle(process);
        free(orig_file);
        free(dll_u8);
        free(out_u8);
        return 1;
    }

    log_line("Wrote rebuilt image to output PE path.");
    log_printf("Bytes changed from memory snapshot: %llu", (unsigned long long)changed_bytes);
    if (changed_bytes == 0) {
        log_line("No section bytes changed. Try a longer wait or debugger-assisted dump.");
        show_error_box("auto_unpack_dump", "No section bytes changed. Try wait_ms=20000+ or use x64dbg+Scylla.");
    }

    TerminateProcess(process, 0);
    CloseHandle(process);
    free(orig_file);
    free(dll_u8);
    free(out_u8);
    return 0;
}

int main(int argc, char **argv) {
    DWORD wait_ms = 8000;
    wchar_t exe_path[MAX_PATH];
    wchar_t *dll_path = NULL;
    wchar_t *out_pe_path = NULL;
    wchar_t *log_path = NULL;
    int result;

    if (GetModuleFileNameW(NULL, exe_path, MAX_PATH) == 0) {
        show_error_box("auto_unpack_dump", "Failed to query executable path.");
        return 1;
    }

    if (argc >= 2 && strcmp(argv[1], "--worker") == 0) {
        if (argc < 4 || !utf8_to_wide(argv[2], &dll_path)) {
            return 2;
        }
        wait_ms = (DWORD)strtoul(argv[3], NULL, 10);
        result = run_worker(dll_path, wait_ms);
        free(dll_path);
        return result;
    }

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
                log_path = _wcsdup(L"auto_unpack_dump.log");
            }
            free(tmp_dll);
            free(tmp_out);
        }
    } else {
        if (!build_default_paths(&dll_path, &out_pe_path, &log_path)) {
            show_error_box("auto_unpack_dump", "Failed to build default paths from EXE location.");
            return 1;
        }
        apply_cwd_fallback_if_needed(&dll_path, &out_pe_path, &log_path);
        if (!file_exists(dll_path) && !prompt_for_dll_path(&dll_path, &out_pe_path, &log_path)) {
            show_error_box("auto_unpack_dump", "No DLL was selected.");
            free(dll_path);
            free(out_pe_path);
            free(log_path);
            return 1;
        }
    }

    g_logf = _wfopen(log_path ? log_path : L"auto_unpack_dump.log", L"wb");
    log_line("=== auto_unpack_dump start ===");
    result = run_controller(exe_path, dll_path, out_pe_path, wait_ms);
    log_line("=== auto_unpack_dump done ===");

    if (g_logf) {
        fclose(g_logf);
    }
    free(dll_path);
    free(out_pe_path);
    free(log_path);
    return result;
}