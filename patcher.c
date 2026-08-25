#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define PATH_CAPACITY 32768
#define PATCH_VERSION L"2.2.0"
#define ACCEPTED_GUID_CAPACITY 64
#define UDK_EULA_CHECK_OFFSET 0x1221B60u
#define UDK_PARITY_BYTES 1048576u
#define UDK_PARITY_HEADER_BYTES 64u
#define UDK_PARITY_HASH_BYTES 32u
#define UDK_PARITY_VERSION 1u

static const char k_udk_exe_original_hash[] = "14B4DC1315598CDE5A5E353AB6A012431D0FE7A0A46F6EDA7D4B42BBE8EB2FA5";
static const char k_udk_exe_patched_hash[] = "EF78C4FD3F3FC8763681E0801DD1655537AF2012D6C1162895521C53404DAAD1";
static const char k_hazard_package_original_hash[] = "24F07FFABDDE0DB7EA45273B1E955194DDEB3C1208CDB5A64F584BF0858A170A";
static const char k_default_engine_original_hash[] = "A6540E384E890611601B4E90194876E7C4AF873CFA90E0FE5D38F450FEE6D413";
static const char k_default_engine_patched_hash[] = "3F85022FE310ED9C42C71DE010EE8C782C902A37F39BFBC3431D93D83A1D1C6F";
static const char k_default_engine_previous_ssaa_hash[] = "1AAB15A27BBE4FE1E875B8B49E34FD17448CFAFFCDDBBBBD17907515E2FC9A2A";
static const char k_default_engine_previous_msaa_hash[] = "B217C4FDF6C33DBD94C99BA9A8AF1BC45590AB3E643E6121DA2694A1059955A8";
static const char k_retired_proxy_v220_hash[] = "E5F894BA14C753474F43FF20771D71DE45E4387E90D5F04772A73BF093A2A6CB";
static const char k_previous_proxy_v210_ssaa_hash[] = "3EDDB292F15E34D8D08AAAE446A398317D37C37835B8B0068F1EF860BBDA4A8E";
static const char k_previous_proxy_v206_hash[] = "5D1D944E437EB215BF081B338C811B1A3F0BC196D14F2C5B917F18C14D2D75E6";
static const char k_previous_proxy_v210_hash[] = "7219946426835041AFA008A3F12DC46648BD23001CF9F2CE9C6D72CECDB36D4C";
static const char k_previous_proxy_v205_hash[] = "0EF55475F65DFD68778AA939837EC89796B92540236EEA2A15798D3ED1492E1C";
static const char k_previous_proxy_v204_hash[] = "FB48F45614A7E0DB8569F6B04A9FCDB0ECE0306E80863A766D143882CD11CE8F";
static const char k_previous_proxy_v203_hash[] = "C971C2B0C5B953A6C8D03BD9325AE5BE66B278F3A945AABBE3F5EBB3DB495057";
static const char k_previous_script_v220_window_modes_hash[] = "5000975874201B3F32CB571C57515E55795469E5BE88B447A6373AB983A63C42";
static const char k_previous_script_v209_hash[] = "7610534F53D6C71AC15D040CA0485C57FE6AF5E41BD49CE213F59EC9B9D670CC";
static const char k_previous_script_v210_ssaa_hash[] = "CBEFE3C9B19C3E75189EC2EA78C06178E0574D0ACD5E51B6470652DE004F399A";
static const char k_previous_script_v210_hash[] = "F28633CB22DA057783730E2C2CBF2BC674D855CF0C9150D59DBD93EDBC5B473F";
static const char k_previous_script_v208_hash[] = "32C5323A3396943D055040D047361FCB4F18B8E5BD2B2ECE4A063C2AA5A18E3B";
static const char k_previous_script_v207_hash[] = "1B3C34CF51BAFE3B7684985EC67D371F43ECCDA3768201EE9841F0D787513D97";
static const char k_previous_script_v206_hash[] = "CEA464817419E539E3BE915C185BF9F477F7AD310F80D93EAB0289501461FD1C";
static const char k_previous_script_v204_hash[] = "669F033193094C26E248070C1C7A23AA868157B6FCE3994B04B6E7AD6E5C94C2";
static const char k_previous_script_v203_hash[] = "1B09E5F2727D67B5981E5751999647E56FB09E923DA265838A91D686D6DFFD35";
static const char k_previous_script_v202_hash[] = "4314104C80FC6A515C23400A29B87840AEB4453B810347E5756373C16D2F2250";
static const char k_previous_script_v202_preview_hash[] = "4CB22F20E0F2FD9610BFBC5C48FC39FFE8AF60E06F42294A6237FFDC8A8393CC";
static const char k_previous_script_v201_hash[] = "E180E62B5EEB92679B86C5A4AED631C8348BB1E7B606D147A1D598976C1E6BC5";
static const char k_previous_script_v200_hash[] = "26518DA4C36CAC3EDA9E70415B1A9BCFEFE2B71AEE6772AF14C8FC900141CBD6";
static const char k_previous_native_v220_window_modes_hash[] = "B36E7B812ABF2668BE86C58EBDBB16960297E369CB8C96047A6EFCA198CEABAD";
static const char k_previous_native_v210_ssaa_hash[] = "2001F55A8CCA37A1728AA299A805B2B82A3D53755CBF3DDB130401696D697AD0";
static const char k_previous_native_v210_hash[] = "43357FB89BDDECFA647E900A6A14A182DBAC8DC2F14F0EB1555F566E30DC9DD7";
static const unsigned char k_udk_parity_magic[8] = {'A', 'C', 'G', 'P', 'A', 'R', '1', 0};
static const unsigned char k_local_map_line[] = "LocalMap=HazardIGFChinaSplit.udk\r\n";
static const unsigned char k_mutator_line[] = "LocalOptions=?Mutator=AntichamberGraphics.AntichamberGraphicsMutator\r\n";
static const unsigned char k_previous_msaa_engine_lines[] = "bAllowD3D9MSAA=True\r\nMaxMultiSamples=1\r\n";
static const unsigned char k_previous_ssaa_engine_lines[] = "bAllowD3D9MSAA=False\r\nMaxMultiSamples=1\r\n";
static const unsigned char k_udk_eula_check_original[] = {0x0F, 0x85, 0x74, 0x02, 0x00, 0x00};
static const unsigned char k_udk_eula_check_patched[] = {0xE9, 0x75, 0x02, 0x00, 0x00, 0x90};
static const unsigned char k_default_settings[] =
    "[AntichamberGraphics.AntichamberGraphicsSettings]\r\n"
    "bConfigured=False\r\n"
    "ResolutionWidth=0\r\n"
    "ResolutionHeight=0\r\n"
    "ResolutionPage=0\r\n";

#include "payload_native.inc"
#include "payload_script.inc"

typedef enum FileState {
    FILE_STATE_MISSING,
    FILE_STATE_ORIGINAL,
    FILE_STATE_PATCHED,
    FILE_STATE_PREVIOUS,
    FILE_STATE_RECOVERABLE,
    FILE_STATE_UNSUPPORTED,
    FILE_STATE_ERROR
} FileState;

typedef struct PatchPaths {
    wchar_t root[PATH_CAPACITY];
    wchar_t udk_exe[PATH_CAPACITY];
    wchar_t udk_parity[PATH_CAPACITY];
    wchar_t install_info[PATH_CAPACITY];
    wchar_t hazard_package[PATH_CAPACITY];
    wchar_t default_engine[PATH_CAPACITY];
    wchar_t retired_proxy[PATH_CAPACITY];
    wchar_t user_code_directory[PATH_CAPACITY];
    wchar_t native_bridge[PATH_CAPACITY];
    wchar_t script_package[PATH_CAPACITY];
    wchar_t settings[PATH_CAPACITY];
} PatchPaths;

typedef struct Preflight {
    FileState udk_exe;
    FileState hazard_package;
    FileState default_engine;
    FileState retired_proxy;
    FileState native_bridge;
    FileState script_package;
    unsigned char native_hash[32];
    unsigned char script_hash[32];
    BOOL accepted_install_record;
    BOOL install_info_accepted;
    wchar_t accepted_guid[ACCEPTED_GUID_CAPACITY];
} Preflight;

static BOOL load_entire_file(const wchar_t *path, unsigned char **bytes_out, size_t *length_out);
static BOOL find_accepted_install_guid(const wchar_t *root, wchar_t guid[ACCEPTED_GUID_CAPACITY]);
static BOOL install_info_has_guid(const wchar_t *path, const wchar_t *guid);
static BOOL stage_udk_parity_recovery(const PatchPaths *paths, unsigned char **bytes_out, size_t *length_out, size_t *recovered_block_out);

static BOOL begin_sha256(HCRYPTPROV *provider, HCRYPTHASH *hash) {
    *provider = 0;
    *hash = 0;
    if (!CryptAcquireContextW(provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (!CryptCreateHash(*provider, CALG_SHA_256, 0, 0, hash)) {
        CryptReleaseContext(*provider, 0);
        *provider = 0;
        return FALSE;
    }
    return TRUE;
}

static BOOL finish_sha256(HCRYPTPROV provider, HCRYPTHASH hash, unsigned char digest[32]) {
    DWORD digest_length = 32;
    BOOL success = CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_length, 0) && digest_length == 32;
    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    return success;
}

static BOOL hash_memory(const unsigned char *bytes, size_t length, unsigned char digest[32]) {
    HCRYPTPROV provider;
    HCRYPTHASH hash;
    size_t offset = 0;
    if (!begin_sha256(&provider, &hash)) return FALSE;
    while (offset < length) {
        DWORD amount = (DWORD)((length - offset) > 1048576u ? 1048576u : (length - offset));
        if (!CryptHashData(hash, bytes + offset, amount, 0)) {
            CryptDestroyHash(hash);
            CryptReleaseContext(provider, 0);
            return FALSE;
        }
        offset += amount;
    }
    return finish_sha256(provider, hash, digest);
}

static BOOL hash_file(const wchar_t *path, unsigned char digest[32], uint64_t *size_out) {
    unsigned char buffer[65536];
    HCRYPTPROV provider;
    HCRYPTHASH hash;
    HANDLE file;
    DWORD amount_read;
    LARGE_INTEGER size;
    BOOL success = FALSE;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || !begin_sha256(&provider, &hash)) {
        CloseHandle(file);
        return FALSE;
    }
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &amount_read, NULL)) break;
        if (amount_read == 0) {
            success = finish_sha256(provider, hash, digest);
            hash = 0;
            provider = 0;
            break;
        }
        if (!CryptHashData(hash, buffer, amount_read, 0)) break;
    }
    if (hash != 0) CryptDestroyHash(hash);
    if (provider != 0) CryptReleaseContext(provider, 0);
    CloseHandle(file);
    if (success && size_out != NULL) *size_out = (uint64_t)size.QuadPart;
    return success;
}

static int hex_digit(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

static BOOL hash_matches_hex(const unsigned char digest[32], const char *expected) {
    size_t index;
    if (strlen(expected) != 64) return FALSE;
    for (index = 0; index < 32; ++index) {
        int high = hex_digit(expected[index * 2]);
        int low = hex_digit(expected[index * 2 + 1]);
        if (high < 0 || low < 0 || digest[index] != (unsigned char)((high << 4) | low)) return FALSE;
    }
    return TRUE;
}

static BOOL hash_from_hex(const char *text, unsigned char digest[32]) {
    size_t index;
    if (strlen(text) != 64) return FALSE;
    for (index = 0; index < 32; ++index) {
        int high = hex_digit(text[index * 2]);
        int low = hex_digit(text[index * 2 + 1]);
        if (high < 0 || low < 0) return FALSE;
        digest[index] = (unsigned char)((high << 4) | low);
    }
    return TRUE;
}

static BOOL hash_matches_previous_script(const unsigned char digest[32]) {
    return hash_matches_hex(digest, k_previous_script_v220_window_modes_hash) || hash_matches_hex(digest, k_previous_script_v210_ssaa_hash) || hash_matches_hex(digest, k_previous_script_v210_hash) || hash_matches_hex(digest, k_previous_script_v209_hash) || hash_matches_hex(digest, k_previous_script_v208_hash) || hash_matches_hex(digest, k_previous_script_v207_hash) || hash_matches_hex(digest, k_previous_script_v206_hash) || hash_matches_hex(digest, k_previous_script_v204_hash) || hash_matches_hex(digest, k_previous_script_v203_hash) || hash_matches_hex(digest, k_previous_script_v202_hash) || hash_matches_hex(digest, k_previous_script_v202_preview_hash) || hash_matches_hex(digest, k_previous_script_v201_hash) || hash_matches_hex(digest, k_previous_script_v200_hash);
}

static BOOL hash_matches_retired_proxy(const unsigned char digest[32]) {
    return hash_matches_hex(digest, k_retired_proxy_v220_hash) || hash_matches_hex(digest, k_previous_proxy_v210_ssaa_hash) || hash_matches_hex(digest, k_previous_proxy_v210_hash) || hash_matches_hex(digest, k_previous_proxy_v206_hash) || hash_matches_hex(digest, k_previous_proxy_v205_hash) || hash_matches_hex(digest, k_previous_proxy_v204_hash) || hash_matches_hex(digest, k_previous_proxy_v203_hash);
}

static BOOL hash_matches_previous_native(const unsigned char digest[32]) {
    return hash_matches_hex(digest, k_previous_native_v220_window_modes_hash) || hash_matches_hex(digest, k_previous_native_v210_ssaa_hash) || hash_matches_hex(digest, k_previous_native_v210_hash);
}

static void hash_to_wide_hex(const unsigned char digest[32], wchar_t text[65]) {
    static const wchar_t digits[] = L"0123456789ABCDEF";
    size_t index;
    for (index = 0; index < 32; ++index) {
        text[index * 2] = digits[digest[index] >> 4];
        text[index * 2 + 1] = digits[digest[index] & 15];
    }
    text[64] = L'\0';
}

static BOOL path_is_file(const wchar_t *path) {
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static BOOL path_is_directory(const wchar_t *path) {
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static BOOL join_path(wchar_t destination[PATH_CAPACITY], const wchar_t *root, const wchar_t *relative) {
    int written = _snwprintf(destination, PATH_CAPACITY, L"%ls\\%ls", root, relative);
    if (written < 0 || written >= PATH_CAPACITY) {
        destination[0] = L'\0';
        return FALSE;
    }
    return TRUE;
}

static BOOL add_suffix(wchar_t destination[PATH_CAPACITY], const wchar_t *path, const wchar_t *suffix) {
    int written = _snwprintf(destination, PATH_CAPACITY, L"%ls%ls", path, suffix);
    if (written < 0 || written >= PATH_CAPACITY) {
        destination[0] = L'\0';
        return FALSE;
    }
    return TRUE;
}

static BOOL initialize_paths(const wchar_t *argument, PatchPaths *paths) {
    DWORD length;
    size_t root_length;
    ZeroMemory(paths, sizeof(*paths));
    length = GetFullPathNameW(argument, PATH_CAPACITY, paths->root, NULL);
    if (length == 0 || length >= PATH_CAPACITY) return FALSE;
    root_length = wcslen(paths->root);
    while (root_length > 3 && (paths->root[root_length - 1] == L'\\' || paths->root[root_length - 1] == L'/')) paths->root[--root_length] = L'\0';
    if (!path_is_directory(paths->root)) return FALSE;
    return join_path(paths->udk_exe, paths->root, L"Binaries\\Win32\\UDK.exe") &&
           add_suffix(paths->udk_parity, paths->udk_exe, L".acgfx.parity") &&
           join_path(paths->install_info, paths->root, L"Binaries\\InstallInfo.xml") &&
           join_path(paths->hazard_package, paths->root, L"UDKGame\\CookedPC\\Hazard.u") &&
           join_path(paths->default_engine, paths->root, L"UDKGame\\Config\\DefaultEngine.ini") &&
           join_path(paths->retired_proxy, paths->root, L"Binaries\\Win32\\d3d9.dll") &&
           join_path(paths->user_code_directory, paths->root, L"Binaries\\Win32\\UserCode") &&
           join_path(paths->native_bridge, paths->root, L"Binaries\\Win32\\UserCode\\AntichamberGraphicsNative.dll") &&
           join_path(paths->script_package, paths->root, L"UDKGame\\CookedPC\\AntichamberGraphics.u") &&
           join_path(paths->settings, paths->root, L"UDKGame\\Config\\UDKAntichamberGraphics.ini");
}

static const wchar_t *state_name(FileState state) {
    switch (state) {
        case FILE_STATE_MISSING: return L"not present";
        case FILE_STATE_ORIGINAL: return L"supported original";
        case FILE_STATE_PATCHED: return L"installed and verified";
        case FILE_STATE_PREVIOUS: return L"supported previous patch";
        case FILE_STATE_RECOVERABLE: return L"recoverable with 1 MiB parity";
        case FILE_STATE_UNSUPPORTED: return L"unsupported hash";
        default: return L"read error";
    }
}

static void print_preflight_line(const wchar_t *label, const wchar_t *value) {
    wprintf(L"%-29ls %ls\n", label, value);
}

static FileState classify_exact_file(const wchar_t *path, const char *expected_hash) {
    unsigned char digest[32];
    if (!path_is_file(path) || !hash_file(path, digest, NULL)) return FILE_STATE_ERROR;
    return hash_matches_hex(digest, expected_hash) ? FILE_STATE_ORIGINAL : FILE_STATE_UNSUPPORTED;
}

static FileState classify_two_hash_file(const wchar_t *path, const char *original_hash, const char *patched_hash) {
    unsigned char digest[32];
    if (!path_is_file(path) || !hash_file(path, digest, NULL)) return FILE_STATE_ERROR;
    if (hash_matches_hex(digest, original_hash)) return FILE_STATE_ORIGINAL;
    if (hash_matches_hex(digest, patched_hash)) return FILE_STATE_PATCHED;
    return FILE_STATE_UNSUPPORTED;
}

static FileState classify_udk_for_unpatch(const PatchPaths *paths) {
    unsigned char digest[32];
    unsigned char *recovered = NULL;
    size_t recovered_length = 0;
    size_t recovered_block = 0;
    if (!path_is_file(paths->udk_exe) || !hash_file(paths->udk_exe, digest, NULL)) return FILE_STATE_ERROR;
    if (hash_matches_hex(digest, k_udk_exe_original_hash)) return FILE_STATE_ORIGINAL;
    if (stage_udk_parity_recovery(paths, &recovered, &recovered_length, &recovered_block)) {
        free(recovered);
        return FILE_STATE_RECOVERABLE;
    }
    return FILE_STATE_UNSUPPORTED;
}

static FileState classify_default_engine(const wchar_t *path) {
    unsigned char digest[32];
    if (!path_is_file(path) || !hash_file(path, digest, NULL)) return FILE_STATE_ERROR;
    if (hash_matches_hex(digest, k_default_engine_original_hash)) return FILE_STATE_ORIGINAL;
    if (hash_matches_hex(digest, k_default_engine_patched_hash)) return FILE_STATE_PATCHED;
    if (hash_matches_hex(digest, k_default_engine_previous_ssaa_hash) || hash_matches_hex(digest, k_default_engine_previous_msaa_hash)) return FILE_STATE_PREVIOUS;
    return FILE_STATE_UNSUPPORTED;
}

static FileState classify_upgradeable_payload(const wchar_t *path, const unsigned char expected_hash[32]) {
    unsigned char digest[32];
    if (!path_is_file(path)) return FILE_STATE_MISSING;
    if (!hash_file(path, digest, NULL)) return FILE_STATE_ERROR;
    if (memcmp(digest, expected_hash, 32) == 0) return FILE_STATE_PATCHED;
    if (hash_matches_previous_script(digest)) return FILE_STATE_PREVIOUS;
    return FILE_STATE_UNSUPPORTED;
}

static FileState classify_retired_proxy(const wchar_t *path) {
    unsigned char digest[32];
    if (!path_is_file(path)) return FILE_STATE_MISSING;
    if (!hash_file(path, digest, NULL)) return FILE_STATE_ERROR;
    if (hash_matches_retired_proxy(digest)) return FILE_STATE_PREVIOUS;
    return FILE_STATE_UNSUPPORTED;
}

static FileState classify_upgradeable_native(const wchar_t *path, const unsigned char expected_hash[32]) {
    unsigned char digest[32];
    if (!path_is_file(path)) return FILE_STATE_MISSING;
    if (!hash_file(path, digest, NULL)) return FILE_STATE_ERROR;
    if (memcmp(digest, expected_hash, 32) == 0) return FILE_STATE_PATCHED;
    if (hash_matches_previous_native(digest)) return FILE_STATE_PREVIOUS;
    return FILE_STATE_UNSUPPORTED;
}

static BOOL run_preflight(const PatchPaths *paths, Preflight *preflight, BOOL show_results, BOOL use_parity_recovery) {
    wchar_t hash_text[65];
    BOOL valid;
    ZeroMemory(preflight, sizeof(*preflight));
    if (!hash_memory(k_payload_native, k_payload_native_size, preflight->native_hash) || !hash_memory(k_payload_script, k_payload_script_size, preflight->script_hash)) return FALSE;
    preflight->udk_exe = use_parity_recovery ? classify_udk_for_unpatch(paths) : classify_two_hash_file(paths->udk_exe, k_udk_exe_original_hash, k_udk_exe_patched_hash);
    preflight->hazard_package = classify_exact_file(paths->hazard_package, k_hazard_package_original_hash);
    preflight->default_engine = classify_default_engine(paths->default_engine);
    preflight->retired_proxy = classify_retired_proxy(paths->retired_proxy);
    preflight->native_bridge = classify_upgradeable_native(paths->native_bridge, preflight->native_hash);
    preflight->script_package = classify_upgradeable_payload(paths->script_package, preflight->script_hash);
    preflight->accepted_install_record = find_accepted_install_guid(paths->root, preflight->accepted_guid);
    preflight->install_info_accepted = preflight->accepted_install_record && install_info_has_guid(paths->install_info, preflight->accepted_guid);
    valid = (preflight->udk_exe == FILE_STATE_ORIGINAL || preflight->udk_exe == FILE_STATE_PATCHED || (use_parity_recovery && preflight->udk_exe == FILE_STATE_RECOVERABLE)) && preflight->hazard_package == FILE_STATE_ORIGINAL &&
            (preflight->default_engine == FILE_STATE_ORIGINAL || preflight->default_engine == FILE_STATE_PATCHED || preflight->default_engine == FILE_STATE_PREVIOUS) &&
            (preflight->retired_proxy == FILE_STATE_MISSING || preflight->retired_proxy == FILE_STATE_PREVIOUS) &&
            (preflight->native_bridge == FILE_STATE_MISSING || preflight->native_bridge == FILE_STATE_PATCHED || preflight->native_bridge == FILE_STATE_PREVIOUS) &&
            (preflight->script_package == FILE_STATE_MISSING || preflight->script_package == FILE_STATE_PATCHED || preflight->script_package == FILE_STATE_PREVIOUS);
    if (show_results) {
        print_preflight_line(L"Game executable:", state_name(preflight->udk_exe));
        if (use_parity_recovery) print_preflight_line(L"UDK recovery parity:", preflight->udk_exe == FILE_STATE_ORIGINAL ? L"not needed; target hash already matches" : (preflight->udk_exe == FILE_STATE_RECOVERABLE ? L"verified; staged output matches target hash" : L"cannot produce the target hash"));
        print_preflight_line(L"Accepted UDK 3 record:", preflight->accepted_install_record ? L"verified for this game directory" : L"not found");
        print_preflight_line(L"InstallInfo.xml:", preflight->install_info_accepted ? L"matches an accepted record" : (preflight->accepted_install_record ? L"will be repaired" : L"cannot be repaired without an accepted record"));
        print_preflight_line(L"Hazard script package:", state_name(preflight->hazard_package));
        print_preflight_line(L"DefaultEngine.ini:", state_name(preflight->default_engine));
        print_preflight_line(L"Retired d3d9.dll cleanup:", preflight->retired_proxy == FILE_STATE_PREVIOUS ? L"verified previous patch; will be removed" : state_name(preflight->retired_proxy));
        print_preflight_line(L"Runtime display detector:", state_name(preflight->native_bridge));
        print_preflight_line(L"In-world menu package:", state_name(preflight->script_package));
        print_preflight_line(L"Persistent graphics settings:", path_is_file(paths->settings) ? L"present (preserved)" : L"not present");
        hash_to_wide_hex(preflight->native_hash, hash_text);
        print_preflight_line(L"Embedded detector SHA-256:", hash_text);
        hash_to_wide_hex(preflight->script_hash, hash_text);
        print_preflight_line(L"Embedded menu SHA-256:", hash_text);
    }
    return valid;
}

static void print_last_error(const wchar_t *action, const wchar_t *path) {
    DWORD error = GetLastError();
    wchar_t *message = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, (wchar_t *)&message, 0, NULL);
    if (message != NULL) {
        size_t length = wcslen(message);
        while (length > 0 && (message[length - 1] == L'\r' || message[length - 1] == L'\n' || message[length - 1] == L' ')) message[--length] = L'\0';
        fwprintf(stderr, L"%ls failed for:\n  %ls\nWindows error %lu: %ls\n", action, path, (unsigned long)error, message);
        LocalFree(message);
    } else {
        fwprintf(stderr, L"%ls failed for:\n  %ls\nWindows error %lu\n", action, path, (unsigned long)error);
    }
}

static BOOL load_entire_file(const wchar_t *path, unsigned char **bytes_out, size_t *length_out) {
    HANDLE file;
    LARGE_INTEGER size;
    unsigned char *bytes;
    size_t offset = 0;
    *bytes_out = NULL;
    *length_out = 0;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || (uint64_t)size.QuadPart > SIZE_MAX) {
        CloseHandle(file);
        return FALSE;
    }
    bytes = (unsigned char *)malloc((size_t)size.QuadPart == 0 ? 1 : (size_t)size.QuadPart);
    if (bytes == NULL) {
        CloseHandle(file);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    while (offset < (size_t)size.QuadPart) {
        DWORD amount_read;
        DWORD request = (DWORD)(((size_t)size.QuadPart - offset) > 1048576u ? 1048576u : ((size_t)size.QuadPart - offset));
        if (!ReadFile(file, bytes + offset, request, &amount_read, NULL) || amount_read == 0) {
            free(bytes);
            CloseHandle(file);
            return FALSE;
        }
        offset += amount_read;
    }
    CloseHandle(file);
    *bytes_out = bytes;
    *length_out = (size_t)size.QuadPart;
    return TRUE;
}

static BOOL write_all(HANDLE file, const unsigned char *bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        DWORD amount_written;
        DWORD request = (DWORD)((length - offset) > 1048576u ? 1048576u : (length - offset));
        if (!WriteFile(file, bytes + offset, request, &amount_written, NULL) || amount_written == 0) return FALSE;
        offset += amount_written;
    }
    return TRUE;
}

static BOOL write_file_atomically(const wchar_t *path, const unsigned char *bytes, size_t length) {
    wchar_t temporary[PATH_CAPACITY];
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD process_id = GetCurrentProcessId();
    unsigned int attempt;
    for (attempt = 0; attempt < 100; ++attempt) {
        int written = _snwprintf(temporary, PATH_CAPACITY, L"%ls.acgfx.%lu.%u.tmp", path, (unsigned long)process_id, attempt);
        if (written < 0 || written >= PATH_CAPACITY) {
            SetLastError(ERROR_FILENAME_EXCED_RANGE);
            return FALSE;
        }
        file = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_FILE_EXISTS) return FALSE;
    }
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!write_all(file, bytes, length) || !FlushFileBuffers(file)) {
        DWORD error = GetLastError();
        CloseHandle(file);
        DeleteFileW(temporary);
        SetLastError(error);
        return FALSE;
    }
    if (!CloseHandle(file)) {
        DWORD error = GetLastError();
        DeleteFileW(temporary);
        SetLastError(error);
        return FALSE;
    }
    if (!MoveFileExW(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD error = GetLastError();
        DeleteFileW(temporary);
        SetLastError(error);
        return FALSE;
    }
    return TRUE;
}

static void write_u32_le(unsigned char *destination, uint32_t value) {
    destination[0] = (unsigned char)value;
    destination[1] = (unsigned char)(value >> 8);
    destination[2] = (unsigned char)(value >> 16);
    destination[3] = (unsigned char)(value >> 24);
}

static void write_u64_le(unsigned char *destination, uint64_t value) {
    write_u32_le(destination, (uint32_t)value);
    write_u32_le(destination + 4, (uint32_t)(value >> 32));
}

static uint32_t read_u32_le(const unsigned char *source) {
    return (uint32_t)source[0] | ((uint32_t)source[1] << 8) | ((uint32_t)source[2] << 16) | ((uint32_t)source[3] << 24);
}

static uint64_t read_u64_le(const unsigned char *source) {
    return (uint64_t)read_u32_le(source) | ((uint64_t)read_u32_le(source + 4) << 32);
}

static BOOL derive_known_original_udk(const wchar_t *path, unsigned char **bytes_out, size_t *length_out) {
    unsigned char *bytes = NULL;
    size_t length = 0;
    unsigned char digest[32];
    if (!load_entire_file(path, &bytes, &length) || !hash_memory(bytes, length, digest)) {
        free(bytes);
        return FALSE;
    }
    if (hash_matches_hex(digest, k_udk_exe_original_hash)) {
        *bytes_out = bytes;
        *length_out = length;
        return TRUE;
    }
    if (!hash_matches_hex(digest, k_udk_exe_patched_hash) || length < UDK_EULA_CHECK_OFFSET + sizeof(k_udk_eula_check_patched) || memcmp(bytes + UDK_EULA_CHECK_OFFSET, k_udk_eula_check_patched, sizeof(k_udk_eula_check_patched)) != 0) {
        free(bytes);
        SetLastError(ERROR_FILE_INVALID);
        return FALSE;
    }
    memcpy(bytes + UDK_EULA_CHECK_OFFSET, k_udk_eula_check_original, sizeof(k_udk_eula_check_original));
    if (!hash_memory(bytes, length, digest) || !hash_matches_hex(digest, k_udk_exe_original_hash)) {
        free(bytes);
        SetLastError(ERROR_CRC);
        return FALSE;
    }
    *bytes_out = bytes;
    *length_out = length;
    return TRUE;
}

static BOOL build_udk_parity_file(const unsigned char *original, size_t original_length, unsigned char **parity_file_out, size_t *parity_file_length_out) {
    unsigned char digest[32];
    unsigned char *parity_file;
    unsigned char *block_hashes;
    unsigned char *parity;
    size_t block_count;
    size_t parity_file_length;
    size_t block_index;
    if (!hash_memory(original, original_length, digest) || !hash_matches_hex(digest, k_udk_exe_original_hash) || original_length == 0) {
        SetLastError(ERROR_FILE_INVALID);
        return FALSE;
    }
    block_count = (original_length + UDK_PARITY_BYTES - 1u) / UDK_PARITY_BYTES;
    if (block_count > UINT32_MAX || block_count > (SIZE_MAX - UDK_PARITY_HEADER_BYTES - UDK_PARITY_BYTES) / UDK_PARITY_HASH_BYTES) {
        SetLastError(ERROR_FILE_TOO_LARGE);
        return FALSE;
    }
    parity_file_length = UDK_PARITY_HEADER_BYTES + block_count * UDK_PARITY_HASH_BYTES + UDK_PARITY_BYTES;
    parity_file = (unsigned char *)calloc(1, parity_file_length);
    if (parity_file == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    memcpy(parity_file, k_udk_parity_magic, sizeof(k_udk_parity_magic));
    write_u32_le(parity_file + 8, UDK_PARITY_VERSION);
    write_u32_le(parity_file + 12, UDK_PARITY_BYTES);
    write_u64_le(parity_file + 16, (uint64_t)original_length);
    write_u32_le(parity_file + 24, (uint32_t)block_count);
    memcpy(parity_file + 32, digest, sizeof(digest));
    block_hashes = parity_file + UDK_PARITY_HEADER_BYTES;
    parity = block_hashes + block_count * UDK_PARITY_HASH_BYTES;
    for (block_index = 0; block_index < block_count; ++block_index) {
        size_t block_offset = block_index * UDK_PARITY_BYTES;
        size_t block_length = original_length - block_offset;
        size_t byte_index;
        if (block_length > UDK_PARITY_BYTES) block_length = UDK_PARITY_BYTES;
        if (!hash_memory(original + block_offset, block_length, block_hashes + block_index * UDK_PARITY_HASH_BYTES)) {
            free(parity_file);
            return FALSE;
        }
        for (byte_index = 0; byte_index < block_length; ++byte_index) parity[byte_index] ^= original[block_offset + byte_index];
    }
    *parity_file_out = parity_file;
    *parity_file_length_out = parity_file_length;
    return TRUE;
}

static BOOL parse_udk_parity_file(const unsigned char *parity_file, size_t parity_file_length, size_t target_length, const unsigned char **block_hashes_out, const unsigned char **parity_out, size_t *block_count_out) {
    unsigned char expected_hash[32];
    uint64_t recorded_target_length;
    uint32_t block_count;
    size_t expected_block_count;
    size_t expected_length;
    if (parity_file_length < UDK_PARITY_HEADER_BYTES || memcmp(parity_file, k_udk_parity_magic, sizeof(k_udk_parity_magic)) != 0 || read_u32_le(parity_file + 8) != UDK_PARITY_VERSION || read_u32_le(parity_file + 12) != UDK_PARITY_BYTES || read_u32_le(parity_file + 28) != 0 || !hash_from_hex(k_udk_exe_original_hash, expected_hash) || memcmp(parity_file + 32, expected_hash, sizeof(expected_hash)) != 0) {
        SetLastError(ERROR_FILE_INVALID);
        return FALSE;
    }
    recorded_target_length = read_u64_le(parity_file + 16);
    block_count = read_u32_le(parity_file + 24);
    expected_block_count = (target_length + UDK_PARITY_BYTES - 1u) / UDK_PARITY_BYTES;
    if (recorded_target_length != (uint64_t)target_length || block_count == 0 || block_count != expected_block_count || block_count > (SIZE_MAX - UDK_PARITY_HEADER_BYTES - UDK_PARITY_BYTES) / UDK_PARITY_HASH_BYTES) {
        SetLastError(ERROR_FILE_INVALID);
        return FALSE;
    }
    expected_length = UDK_PARITY_HEADER_BYTES + (size_t)block_count * UDK_PARITY_HASH_BYTES + UDK_PARITY_BYTES;
    if (parity_file_length != expected_length) {
        SetLastError(ERROR_FILE_INVALID);
        return FALSE;
    }
    *block_hashes_out = parity_file + UDK_PARITY_HEADER_BYTES;
    *parity_out = parity_file + UDK_PARITY_HEADER_BYTES + (size_t)block_count * UDK_PARITY_HASH_BYTES;
    *block_count_out = block_count;
    return TRUE;
}

static BOOL stage_udk_parity_recovery(const PatchPaths *paths, unsigned char **bytes_out, size_t *length_out, size_t *recovered_block_out) {
    unsigned char *current = NULL;
    unsigned char *parity_file = NULL;
    unsigned char *reconstructed_block = NULL;
    const unsigned char *block_hashes;
    const unsigned char *parity;
    unsigned char digest[32];
    size_t current_length = 0;
    size_t parity_file_length = 0;
    size_t block_count;
    size_t block_index;
    size_t mismatched_block = SIZE_MAX;
    size_t mismatch_count = 0;
    *bytes_out = NULL;
    *length_out = 0;
    *recovered_block_out = SIZE_MAX;
    if (!load_entire_file(paths->udk_exe, &current, &current_length) || !load_entire_file(paths->udk_parity, &parity_file, &parity_file_length) || !parse_udk_parity_file(parity_file, parity_file_length, current_length, &block_hashes, &parity, &block_count)) goto failed;
    for (block_index = 0; block_index < block_count; ++block_index) {
        size_t block_offset = block_index * UDK_PARITY_BYTES;
        size_t block_length = current_length - block_offset;
        if (block_length > UDK_PARITY_BYTES) block_length = UDK_PARITY_BYTES;
        if (!hash_memory(current + block_offset, block_length, digest)) goto failed;
        if (memcmp(digest, block_hashes + block_index * UDK_PARITY_HASH_BYTES, UDK_PARITY_HASH_BYTES) != 0) {
            mismatched_block = block_index;
            ++mismatch_count;
        }
    }
    if (mismatch_count != 1) {
        SetLastError(ERROR_CRC);
        goto failed;
    }
    reconstructed_block = (unsigned char *)malloc(UDK_PARITY_BYTES);
    if (reconstructed_block == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        goto failed;
    }
    memcpy(reconstructed_block, parity, UDK_PARITY_BYTES);
    for (block_index = 0; block_index < block_count; ++block_index) {
        size_t block_offset;
        size_t block_length;
        size_t byte_index;
        if (block_index == mismatched_block) continue;
        block_offset = block_index * UDK_PARITY_BYTES;
        block_length = current_length - block_offset;
        if (block_length > UDK_PARITY_BYTES) block_length = UDK_PARITY_BYTES;
        for (byte_index = 0; byte_index < block_length; ++byte_index) reconstructed_block[byte_index] ^= current[block_offset + byte_index];
    }
    {
        size_t recovered_offset = mismatched_block * UDK_PARITY_BYTES;
        size_t recovered_length = current_length - recovered_offset;
        if (recovered_length > UDK_PARITY_BYTES) recovered_length = UDK_PARITY_BYTES;
        if (!hash_memory(reconstructed_block, recovered_length, digest) || memcmp(digest, block_hashes + mismatched_block * UDK_PARITY_HASH_BYTES, UDK_PARITY_HASH_BYTES) != 0) {
            SetLastError(ERROR_CRC);
            goto failed;
        }
        memcpy(current + recovered_offset, reconstructed_block, recovered_length);
    }
    if (!hash_memory(current, current_length, digest) || !hash_matches_hex(digest, k_udk_exe_original_hash)) {
        SetLastError(ERROR_CRC);
        goto failed;
    }
    free(reconstructed_block);
    free(parity_file);
    *bytes_out = current;
    *length_out = current_length;
    *recovered_block_out = mismatched_block;
    return TRUE;
failed:
    free(reconstructed_block);
    free(parity_file);
    free(current);
    return FALSE;
}

static BOOL ensure_udk_parity(const PatchPaths *paths, BOOL *created, unsigned char parity_file_hash[32]) {
    unsigned char *original = NULL;
    unsigned char *expected_parity_file = NULL;
    unsigned char *existing_parity_file = NULL;
    size_t original_length = 0;
    size_t expected_length = 0;
    size_t existing_length = 0;
    unsigned char installed_hash[32];
    BOOL success = FALSE;
    *created = FALSE;
    if (!derive_known_original_udk(paths->udk_exe, &original, &original_length) || !build_udk_parity_file(original, original_length, &expected_parity_file, &expected_length) || !hash_memory(expected_parity_file, expected_length, parity_file_hash)) goto finished;
    if (path_is_file(paths->udk_parity)) {
        if (!load_entire_file(paths->udk_parity, &existing_parity_file, &existing_length) || existing_length != expected_length || memcmp(existing_parity_file, expected_parity_file, expected_length) != 0) {
            fwprintf(stderr, L"Refusing to overwrite unexpected UDK recovery parity:\n  %ls\n", paths->udk_parity);
            SetLastError(ERROR_FILE_INVALID);
            goto finished;
        }
        success = TRUE;
        goto finished;
    }
    if (!write_file_atomically(paths->udk_parity, expected_parity_file, expected_length) || !hash_file(paths->udk_parity, installed_hash, NULL) || memcmp(installed_hash, parity_file_hash, sizeof(installed_hash)) != 0) {
        DeleteFileW(paths->udk_parity);
        SetLastError(ERROR_CRC);
        goto finished;
    }
    *created = TRUE;
    success = TRUE;
finished:
    free(existing_parity_file);
    free(expected_parity_file);
    free(original);
    return success;
}

static BOOL restore_udk_exe_with_parity(const PatchPaths *paths) {
    unsigned char digest[32];
    unsigned char *recovered = NULL;
    size_t recovered_length = 0;
    size_t recovered_block = SIZE_MAX;
    if (hash_file(paths->udk_exe, digest, NULL) && hash_matches_hex(digest, k_udk_exe_original_hash)) return TRUE;
    if (!stage_udk_parity_recovery(paths, &recovered, &recovered_length, &recovered_block)) return FALSE;
    if (!write_file_atomically(paths->udk_exe, recovered, recovered_length) || !hash_file(paths->udk_exe, digest, NULL) || !hash_matches_hex(digest, k_udk_exe_original_hash)) {
        free(recovered);
        SetLastError(ERROR_CRC);
        return FALSE;
    }
    free(recovered);
    return TRUE;
}

static void trim_path_end(wchar_t *path) {
    size_t length = wcslen(path);
    while (length > 3 && (path[length - 1] == L'\\' || path[length - 1] == L'/')) path[--length] = L'\0';
}

static BOOL paths_match(const wchar_t *left, const wchar_t *right) {
    wchar_t left_full[PATH_CAPACITY];
    wchar_t right_full[PATH_CAPACITY];
    DWORD left_length = GetFullPathNameW(left, PATH_CAPACITY, left_full, NULL);
    DWORD right_length = GetFullPathNameW(right, PATH_CAPACITY, right_full, NULL);
    if (left_length == 0 || left_length >= PATH_CAPACITY || right_length == 0 || right_length >= PATH_CAPACITY) return FALSE;
    trim_path_end(left_full);
    trim_path_end(right_full);
    return _wcsicmp(left_full, right_full) == 0;
}

static BOOL accepted_uninstall_key_matches(HKEY uninstall_root, const wchar_t *key_name, const wchar_t *game_root) {
    HKEY key;
    DWORD accepted = 0;
    DWORD accepted_size = sizeof(accepted);
    DWORD accepted_type = 0;
    DWORD location_type = 0;
    DWORD location_size = PATH_CAPACITY * sizeof(wchar_t);
    wchar_t location[PATH_CAPACITY];
    wchar_t expanded[PATH_CAPACITY];
    const wchar_t *comparison_location = location;
    BOOL matches = FALSE;
    if (RegOpenKeyExW(uninstall_root, key_name, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return FALSE;
    ZeroMemory(location, sizeof(location));
    if (RegQueryValueExW(key, L"EULAAccepted", NULL, &accepted_type, (BYTE *)&accepted, &accepted_size) == ERROR_SUCCESS && accepted_type == REG_DWORD && accepted == 1 &&
        RegQueryValueExW(key, L"InstallLocation", NULL, &location_type, (BYTE *)location, &location_size) == ERROR_SUCCESS && (location_type == REG_SZ || location_type == REG_EXPAND_SZ)) {
        location[PATH_CAPACITY - 1] = L'\0';
        if (location_type == REG_EXPAND_SZ) {
            DWORD expanded_length = ExpandEnvironmentStringsW(location, expanded, PATH_CAPACITY);
            if (expanded_length > 0 && expanded_length < PATH_CAPACITY) comparison_location = expanded;
        }
        matches = paths_match(comparison_location, game_root);
    }
    RegCloseKey(key);
    return matches;
}

static BOOL find_accepted_install_guid(const wchar_t *root, wchar_t guid[ACCEPTED_GUID_CAPACITY]) {
    static const wchar_t uninstall_path[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    const REGSAM views[] = {KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    size_t view_index;
    guid[0] = L'\0';
    for (view_index = 0; view_index < sizeof(views) / sizeof(views[0]); ++view_index) {
        HKEY uninstall_root;
        DWORD index;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, uninstall_path, 0, KEY_ENUMERATE_SUB_KEYS | views[view_index], &uninstall_root) != ERROR_SUCCESS) continue;
        for (index = 0;; ++index) {
            wchar_t key_name[256];
            DWORD key_name_length = sizeof(key_name) / sizeof(key_name[0]);
            LONG result = RegEnumKeyExW(uninstall_root, index, key_name, &key_name_length, NULL, NULL, NULL, NULL);
            size_t guid_length;
            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result != ERROR_SUCCESS || _wcsnicmp(key_name, L"UDK-", 4) != 0) continue;
            guid_length = wcslen(key_name + 4);
            if (guid_length == 0 || guid_length >= ACCEPTED_GUID_CAPACITY || !accepted_uninstall_key_matches(uninstall_root, key_name, root)) continue;
            wcscpy(guid, key_name + 4);
            RegCloseKey(uninstall_root);
            return TRUE;
        }
        RegCloseKey(uninstall_root);
    }
    return FALSE;
}

static BOOL wide_guid_to_utf8(const wchar_t *guid, char output[ACCEPTED_GUID_CAPACITY * 4]) {
    int length = WideCharToMultiByte(CP_UTF8, 0, guid, -1, output, ACCEPTED_GUID_CAPACITY * 4, NULL, NULL);
    return length > 1;
}

static BOOL bytes_contain(const unsigned char *bytes, size_t length, const unsigned char *needle, size_t needle_length) {
    size_t offset;
    if (needle_length == 0 || needle_length > length) return FALSE;
    for (offset = 0; offset <= length - needle_length; ++offset) {
        if (memcmp(bytes + offset, needle, needle_length) == 0) return TRUE;
    }
    return FALSE;
}

static BOOL install_info_has_guid(const wchar_t *path, const wchar_t *guid) {
    unsigned char *bytes = NULL;
    size_t length = 0;
    char guid_utf8[ACCEPTED_GUID_CAPACITY * 4];
    char needle[ACCEPTED_GUID_CAPACITY * 4 + 64];
    int needle_length;
    BOOL matches = FALSE;
    if (!wide_guid_to_utf8(guid, guid_utf8) || !load_entire_file(path, &bytes, &length)) return FALSE;
    needle_length = _snprintf(needle, sizeof(needle), "<InstallGuidString>%s</InstallGuidString>", guid_utf8);
    if (needle_length > 0 && (size_t)needle_length < sizeof(needle)) matches = bytes_contain(bytes, length, (const unsigned char *)needle, (size_t)needle_length);
    free(bytes);
    return matches;
}

static BOOL repair_install_info(const PatchPaths *paths, const wchar_t *guid, unsigned char **previous_bytes, size_t *previous_length, BOOL *changed) {
    char guid_utf8[ACCEPTED_GUID_CAPACITY * 4];
    char xml[1024];
    int xml_length;
    unsigned char *loaded = NULL;
    size_t loaded_length = 0;
    *previous_bytes = NULL;
    *previous_length = 0;
    *changed = FALSE;
    if (install_info_has_guid(paths->install_info, guid)) return TRUE;
    if (!wide_guid_to_utf8(guid, guid_utf8)) return FALSE;
    if (path_is_file(paths->install_info) && !load_entire_file(paths->install_info, &loaded, &loaded_length)) return FALSE;
    xml_length = _snprintf(xml, sizeof(xml), "<?xml version=\"1.0\"?>\r\n<InstallInfo xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\r\n  <InstallGuidString>%s</InstallGuidString>\r\n</InstallInfo>\r\n", guid_utf8);
    if (xml_length <= 0 || (size_t)xml_length >= sizeof(xml) || !write_file_atomically(paths->install_info, (const unsigned char *)xml, (size_t)xml_length) || !install_info_has_guid(paths->install_info, guid)) {
        free(loaded);
        return FALSE;
    }
    *previous_bytes = loaded;
    *previous_length = loaded_length;
    *changed = TRUE;
    return TRUE;
}

static BOOL restore_install_info(const PatchPaths *paths, const unsigned char *previous_bytes, size_t previous_length) {
    if (previous_bytes == NULL) return DeleteFileW(paths->install_info) || GetLastError() == ERROR_FILE_NOT_FOUND;
    return write_file_atomically(paths->install_info, previous_bytes, previous_length);
}

static BOOL ensure_original_backup_from_memory(const wchar_t *path, const char *expected_hash, const unsigned char *bytes, size_t length, wchar_t backup[PATH_CAPACITY]) {
    unsigned char digest[32];
    if (!hash_memory(bytes, length, digest) || !hash_matches_hex(digest, expected_hash) || !add_suffix(backup, path, L".acgfx.bak")) return FALSE;
    if (path_is_file(backup)) {
        if (!hash_file(backup, digest, NULL) || !hash_matches_hex(digest, expected_hash)) {
            fwprintf(stderr, L"Refusing to overwrite an unexpected backup:\n  %ls\n", backup);
            SetLastError(ERROR_FILE_INVALID);
            return FALSE;
        }
        return TRUE;
    }
    if (!write_file_atomically(backup, bytes, length) || !hash_file(backup, digest, NULL) || !hash_matches_hex(digest, expected_hash)) {
        fwprintf(stderr, L"The new backup failed hash verification:\n  %ls\n", backup);
        DeleteFileW(backup);
        SetLastError(ERROR_CRC);
        return FALSE;
    }
    return TRUE;
}

static BOOL patch_udk_exe(const PatchPaths *paths) {
    unsigned char *bytes = NULL;
    size_t length = 0;
    unsigned char digest[32];
    BOOL success = FALSE;
    if (!load_entire_file(paths->udk_exe, &bytes, &length)) {
        print_last_error(L"Reading UDK.exe", paths->udk_exe);
        goto finished;
    }
    if (!hash_memory(bytes, length, digest) || !hash_matches_hex(digest, k_udk_exe_original_hash) || length < UDK_EULA_CHECK_OFFSET + sizeof(k_udk_eula_check_original) || memcmp(bytes + UDK_EULA_CHECK_OFFSET, k_udk_eula_check_original, sizeof(k_udk_eula_check_original)) != 0) {
        fwprintf(stderr, L"UDK.exe changed after preflight; the accepted-EULA safeguard was not applied.\n");
        goto finished;
    }
    memcpy(bytes + UDK_EULA_CHECK_OFFSET, k_udk_eula_check_patched, sizeof(k_udk_eula_check_patched));
    if (!hash_memory(bytes, length, digest) || !hash_matches_hex(digest, k_udk_exe_patched_hash)) {
        fwprintf(stderr, L"The staged UDK.exe safeguard failed its output hash check.\n");
        goto finished;
    }
    if (!write_file_atomically(paths->udk_exe, bytes, length)) {
        print_last_error(L"Installing accepted-EULA safeguard", paths->udk_exe);
        goto finished;
    }
    if (!hash_file(paths->udk_exe, digest, NULL) || !hash_matches_hex(digest, k_udk_exe_patched_hash)) {
        fwprintf(stderr, L"The installed UDK.exe safeguard failed its final hash check.\n");
        memcpy(bytes + UDK_EULA_CHECK_OFFSET, k_udk_eula_check_original, sizeof(k_udk_eula_check_original));
        if (!write_file_atomically(paths->udk_exe, bytes, length)) fwprintf(stderr, L"Warning: restoring the in-memory verified UDK.exe also failed.\n");
        goto finished;
    }
    success = TRUE;
finished:
    free(bytes);
    return success;
}

static BOOL restore_udk_exe(const PatchPaths *paths) {
    wchar_t backup[PATH_CAPACITY];
    unsigned char *bytes = NULL;
    size_t length = 0;
    unsigned char digest[32];
    BOOL success = FALSE;
    if (!add_suffix(backup, paths->udk_exe, L".acgfx.bak")) return FALSE;
    if (path_is_file(backup) && load_entire_file(backup, &bytes, &length)) {
        if (hash_memory(bytes, length, digest) && hash_matches_hex(digest, k_udk_exe_original_hash) && write_file_atomically(paths->udk_exe, bytes, length) && hash_file(paths->udk_exe, digest, NULL) && hash_matches_hex(digest, k_udk_exe_original_hash)) success = TRUE;
        free(bytes);
        if (success) return TRUE;
        bytes = NULL;
        length = 0;
    }
    if (!load_entire_file(paths->udk_exe, &bytes, &length)) return FALSE;
    if (hash_memory(bytes, length, digest) && hash_matches_hex(digest, k_udk_exe_patched_hash) && length >= UDK_EULA_CHECK_OFFSET + sizeof(k_udk_eula_check_patched) && memcmp(bytes + UDK_EULA_CHECK_OFFSET, k_udk_eula_check_patched, sizeof(k_udk_eula_check_patched)) == 0) {
        memcpy(bytes + UDK_EULA_CHECK_OFFSET, k_udk_eula_check_original, sizeof(k_udk_eula_check_original));
        if (hash_memory(bytes, length, digest) && hash_matches_hex(digest, k_udk_exe_original_hash) && write_file_atomically(paths->udk_exe, bytes, length) && hash_file(paths->udk_exe, digest, NULL) && hash_matches_hex(digest, k_udk_exe_original_hash)) success = TRUE;
    }
    free(bytes);
    return success;
}

static size_t pattern_count(const unsigned char *bytes, size_t length, const unsigned char *pattern, size_t pattern_length, size_t *offset_out) {
    size_t offset;
    size_t count = 0;
    if (length < pattern_length || pattern_length == 0) return 0;
    for (offset = 0; offset <= length - pattern_length; ++offset) {
        if (memcmp(bytes + offset, pattern, pattern_length) == 0) {
            if (offset_out != NULL) *offset_out = offset;
            ++count;
        }
    }
    return count;
}

static BOOL insert_after_once(const unsigned char *bytes, size_t length, const unsigned char *pattern, size_t pattern_length, const unsigned char *insertion, size_t insertion_length, unsigned char **output, size_t *output_length) {
    size_t offset = 0;
    size_t prefix_length;
    unsigned char *result;
    *output = NULL;
    *output_length = 0;
    if (pattern_count(bytes, length, pattern, pattern_length, &offset) != 1 || length > SIZE_MAX - insertion_length) return FALSE;
    result = (unsigned char *)malloc(length + insertion_length);
    if (result == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    prefix_length = offset + pattern_length;
    memcpy(result, bytes, prefix_length);
    memcpy(result + prefix_length, insertion, insertion_length);
    memcpy(result + prefix_length + insertion_length, bytes + prefix_length, length - prefix_length);
    *output = result;
    *output_length = length + insertion_length;
    return TRUE;
}

static BOOL remove_once(const unsigned char *bytes, size_t length, const unsigned char *pattern, size_t pattern_length, unsigned char **output, size_t *output_length) {
    size_t offset = 0;
    unsigned char *result;
    *output = NULL;
    *output_length = 0;
    if (pattern_count(bytes, length, pattern, pattern_length, &offset) != 1) return FALSE;
    result = (unsigned char *)malloc(length - pattern_length == 0 ? 1 : length - pattern_length);
    if (result == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    memcpy(result, bytes, offset);
    memcpy(result + offset, bytes + offset + pattern_length, length - offset - pattern_length);
    *output = result;
    *output_length = length - pattern_length;
    return TRUE;
}

static BOOL patch_default_engine(const PatchPaths *paths) {
    unsigned char *current = NULL;
    unsigned char *with_mutator = NULL;
    unsigned char *without_previous_settings = NULL;
    unsigned char *derived_original = NULL;
    const unsigned char *patched;
    const unsigned char *backup_bytes;
    size_t current_length = 0;
    size_t with_mutator_length = 0;
    size_t without_previous_settings_length = 0;
    size_t patched_length = 0;
    size_t derived_original_length = 0;
    size_t backup_length;
    unsigned char digest[32];
    wchar_t backup[PATH_CAPACITY];
    BOOL success = FALSE;
    if (!load_entire_file(paths->default_engine, &current, &current_length)) {
        print_last_error(L"Reading DefaultEngine.ini", paths->default_engine);
        goto finished;
    }
    if (!hash_memory(current, current_length, digest)) goto finished;
    if (hash_matches_hex(digest, k_default_engine_original_hash)) {
        if (!insert_after_once(current, current_length, k_local_map_line, sizeof(k_local_map_line) - 1, k_mutator_line, sizeof(k_mutator_line) - 1, &with_mutator, &with_mutator_length)) {
            fwprintf(stderr, L"The validated LocalMap line was not unique in DefaultEngine.ini.\n");
            goto finished;
        }
        patched = with_mutator;
        patched_length = with_mutator_length;
        backup_bytes = current;
        backup_length = current_length;
    } else if (hash_matches_hex(digest, k_default_engine_previous_ssaa_hash)) {
        if (!remove_once(current, current_length, k_previous_ssaa_engine_lines, sizeof(k_previous_ssaa_engine_lines) - 1, &without_previous_settings, &without_previous_settings_length) || !remove_once(without_previous_settings, without_previous_settings_length, k_mutator_line, sizeof(k_mutator_line) - 1, &derived_original, &derived_original_length) || !hash_memory(derived_original, derived_original_length, digest) || !hash_matches_hex(digest, k_default_engine_original_hash)) {
            fwprintf(stderr, L"Could not remove the previous SSAA configuration from verified DefaultEngine.ini.\n");
            goto finished;
        }
        patched = without_previous_settings;
        patched_length = without_previous_settings_length;
        backup_bytes = derived_original;
        backup_length = derived_original_length;
    } else if (hash_matches_hex(digest, k_default_engine_previous_msaa_hash)) {
        if (!remove_once(current, current_length, k_previous_msaa_engine_lines, sizeof(k_previous_msaa_engine_lines) - 1, &without_previous_settings, &without_previous_settings_length) || !remove_once(without_previous_settings, without_previous_settings_length, k_mutator_line, sizeof(k_mutator_line) - 1, &derived_original, &derived_original_length) || !hash_memory(derived_original, derived_original_length, digest) || !hash_matches_hex(digest, k_default_engine_original_hash)) {
            fwprintf(stderr, L"Could not derive the verified original from the previous MSAA configuration patch.\n");
            goto finished;
        }
        patched = without_previous_settings;
        patched_length = without_previous_settings_length;
        backup_bytes = derived_original;
        backup_length = derived_original_length;
    } else {
        fwprintf(stderr, L"DefaultEngine.ini changed after preflight; no configuration patch was applied.\n");
        goto finished;
    }
    if (!hash_memory(patched, patched_length, digest) || !hash_matches_hex(digest, k_default_engine_patched_hash)) {
        fwprintf(stderr, L"The staged DefaultEngine.ini patch failed its output hash check.\n");
        goto finished;
    }
    if (!ensure_original_backup_from_memory(paths->default_engine, k_default_engine_original_hash, backup_bytes, backup_length, backup)) goto finished;
    if (!write_file_atomically(paths->default_engine, patched, patched_length)) {
        print_last_error(L"Installing DefaultEngine.ini patch", paths->default_engine);
        goto finished;
    }
    if (!hash_file(paths->default_engine, digest, NULL) || !hash_matches_hex(digest, k_default_engine_patched_hash)) {
        fwprintf(stderr, L"The installed DefaultEngine.ini failed its final hash check.\n");
        if (!write_file_atomically(paths->default_engine, current, current_length)) fwprintf(stderr, L"Warning: restoring the previous verified DefaultEngine.ini also failed.\n");
        goto finished;
    }
    success = TRUE;
finished:
    free(derived_original);
    free(without_previous_settings);
    free(with_mutator);
    free(current);
    return success;
}

static BOOL restore_default_engine(const PatchPaths *paths) {
    wchar_t backup[PATH_CAPACITY];
    unsigned char *bytes = NULL;
    unsigned char *without_graphics = NULL;
    unsigned char *restored = NULL;
    size_t length = 0;
    size_t without_graphics_length = 0;
    size_t restored_length = 0;
    unsigned char digest[32];
    BOOL success = FALSE;
    if (!add_suffix(backup, paths->default_engine, L".acgfx.bak")) return FALSE;
    if (path_is_file(backup) && load_entire_file(backup, &bytes, &length)) {
        if (hash_memory(bytes, length, digest) && hash_matches_hex(digest, k_default_engine_original_hash) && write_file_atomically(paths->default_engine, bytes, length) && hash_file(paths->default_engine, digest, NULL) && hash_matches_hex(digest, k_default_engine_original_hash)) success = TRUE;
        free(bytes);
        if (success) return TRUE;
        bytes = NULL;
        length = 0;
    }
    if (!load_entire_file(paths->default_engine, &bytes, &length)) return FALSE;
    if (!hash_memory(bytes, length, digest)) goto finished;
    if (hash_matches_hex(digest, k_default_engine_patched_hash)) {
        if (!remove_once(bytes, length, k_mutator_line, sizeof(k_mutator_line) - 1, &restored, &restored_length)) goto finished;
    } else if (hash_matches_hex(digest, k_default_engine_previous_ssaa_hash)) {
        if (!remove_once(bytes, length, k_previous_ssaa_engine_lines, sizeof(k_previous_ssaa_engine_lines) - 1, &without_graphics, &without_graphics_length) || !remove_once(without_graphics, without_graphics_length, k_mutator_line, sizeof(k_mutator_line) - 1, &restored, &restored_length)) goto finished;
    } else if (hash_matches_hex(digest, k_default_engine_previous_msaa_hash)) {
        if (!remove_once(bytes, length, k_previous_msaa_engine_lines, sizeof(k_previous_msaa_engine_lines) - 1, &without_graphics, &without_graphics_length) || !remove_once(without_graphics, without_graphics_length, k_mutator_line, sizeof(k_mutator_line) - 1, &restored, &restored_length)) goto finished;
    } else {
        goto finished;
    }
    if (restored != NULL) {
        if (hash_memory(restored, restored_length, digest) && hash_matches_hex(digest, k_default_engine_original_hash) && write_file_atomically(paths->default_engine, restored, restored_length) && hash_file(paths->default_engine, digest, NULL) && hash_matches_hex(digest, k_default_engine_original_hash)) success = TRUE;
    }
finished:
    free(without_graphics);
    free(restored);
    free(bytes);
    return success;
}

static BOOL ensure_directory(const wchar_t *path) {
    if (path_is_directory(path)) return TRUE;
    if (CreateDirectoryW(path, NULL)) return TRUE;
    return GetLastError() == ERROR_ALREADY_EXISTS && path_is_directory(path);
}

static BOOL install_payload_file(const wchar_t *path, const unsigned char *bytes, size_t length, const unsigned char expected_hash[32], FileState state, BOOL *created) {
    unsigned char digest[32];
    *created = FALSE;
    if (state == FILE_STATE_PATCHED) return TRUE;
    if (state != FILE_STATE_MISSING || path_is_file(path)) {
        SetLastError(ERROR_FILE_EXISTS);
        return FALSE;
    }
    if (!write_file_atomically(path, bytes, length)) return FALSE;
    *created = TRUE;
    if (!hash_file(path, digest, NULL) || memcmp(digest, expected_hash, 32) != 0) {
        DeleteFileW(path);
        *created = FALSE;
        SetLastError(ERROR_CRC);
        return FALSE;
    }
    return TRUE;
}

typedef BOOL (*PreviousHashMatcher)(const unsigned char digest[32]);

static BOOL upgrade_payload_file(const wchar_t *path, const unsigned char *bytes, size_t length, const unsigned char expected_hash[32], PreviousHashMatcher matches_previous, unsigned char **previous_bytes, size_t *previous_length) {
    unsigned char digest[32];
    unsigned char *loaded = NULL;
    size_t loaded_length = 0;
    *previous_bytes = NULL;
    *previous_length = 0;
    if (!load_entire_file(path, &loaded, &loaded_length)) return FALSE;
    if (!hash_memory(loaded, loaded_length, digest) || !matches_previous(digest)) {
        free(loaded);
        SetLastError(ERROR_CRC);
        return FALSE;
    }
    if (!write_file_atomically(path, bytes, length)) {
        free(loaded);
        return FALSE;
    }
    if (!hash_file(path, digest, NULL) || memcmp(digest, expected_hash, 32) != 0) {
        DWORD error = ERROR_CRC;
        if (!write_file_atomically(path, loaded, loaded_length)) error = GetLastError();
        free(loaded);
        SetLastError(error);
        return FALSE;
    }
    *previous_bytes = loaded;
    *previous_length = loaded_length;
    return TRUE;
}

static BOOL restore_upgraded_payload(const wchar_t *path, const unsigned char expected_hash[32], PreviousHashMatcher matches_previous, const unsigned char *previous_bytes, size_t previous_length) {
    unsigned char digest[32];
    if (!path_is_file(path) || !hash_file(path, digest, NULL) || memcmp(digest, expected_hash, 32) != 0) return FALSE;
    if (!hash_memory(previous_bytes, previous_length, digest) || !matches_previous(digest)) return FALSE;
    if (!write_file_atomically(path, previous_bytes, previous_length)) return FALSE;
    return hash_file(path, digest, NULL) && matches_previous(digest);
}

static BOOL delete_if_hash_matches(const wchar_t *path, const unsigned char expected_hash[32]) {
    unsigned char digest[32];
    if (!path_is_file(path)) return TRUE;
    if (!hash_file(path, digest, NULL) || memcmp(digest, expected_hash, 32) != 0) return FALSE;
    return DeleteFileW(path);
}

static BOOL move_payload_recoverably(const wchar_t *path, const unsigned char expected_hash[32]) {
    wchar_t destination[PATH_CAPACITY];
    unsigned char digest[32];
    unsigned int index;
    if (!path_is_file(path)) return TRUE;
    if (!hash_file(path, digest, NULL) || memcmp(digest, expected_hash, 32) != 0) return FALSE;
    for (index = 0; index < 100; ++index) {
        int written;
        if (index == 0) written = _snwprintf(destination, PATH_CAPACITY, L"%ls.acgfx.removed", path);
        else written = _snwprintf(destination, PATH_CAPACITY, L"%ls.acgfx.removed.%u", path, index);
        if (written < 0 || written >= PATH_CAPACITY) return FALSE;
        if (path_is_file(destination)) {
            if (hash_file(destination, digest, NULL) && memcmp(digest, expected_hash, 32) == 0) return DeleteFileW(path);
            continue;
        }
        return MoveFileExW(path, destination, MOVEFILE_WRITE_THROUGH);
    }
    SetLastError(ERROR_TOO_MANY_NAMES);
    return FALSE;
}

static BOOL game_is_running(void) {
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    BOOL found = FALSE;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return TRUE;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"UDK.exe") == 0) {
                found = TRUE;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

static BOOL config_line_has_key(const unsigned char *line, size_t length, const char *key) {
    size_t line_index = 0;
    size_t key_index;
    while (line_index < length && (line[line_index] == ' ' || line[line_index] == '\t')) ++line_index;
    for (key_index = 0; key[key_index] != '\0'; ++key_index) {
        unsigned char actual;
        unsigned char expected;
        if (line_index + key_index >= length) return FALSE;
        actual = line[line_index + key_index];
        expected = (unsigned char)key[key_index];
        if (actual >= 'A' && actual <= 'Z') actual = (unsigned char)(actual - 'A' + 'a');
        if (expected >= 'A' && expected <= 'Z') expected = (unsigned char)(expected - 'A' + 'a');
        if (actual != expected) return FALSE;
    }
    return line_index + key_index < length && line[line_index + key_index] == '=';
}

static BOOL strip_retired_settings(const unsigned char *bytes, size_t length, unsigned char **output, size_t *output_length, BOOL *changed) {
    static const char *retired_keys[] = {"bSupersamplingEnabled", "OutputResolutionWidth", "OutputResolutionHeight", "bDisplayModeConfigured", "bFullscreenEnabled", "DisplayMode"};
    unsigned char *result;
    size_t input_offset = 0;
    size_t result_length = 0;
    *output = NULL;
    *output_length = 0;
    *changed = FALSE;
    result = (unsigned char *)malloc(length != 0 ? length : 1);
    if (result == NULL) return FALSE;
    while (input_offset < length) {
        size_t line_start = input_offset;
        size_t content_length;
        size_t line_length;
        size_t key_index;
        BOOL remove_line = FALSE;
        while (input_offset < length && bytes[input_offset] != '\r' && bytes[input_offset] != '\n') ++input_offset;
        content_length = input_offset - line_start;
        if (input_offset < length && bytes[input_offset] == '\r') ++input_offset;
        if (input_offset < length && bytes[input_offset] == '\n') ++input_offset;
        line_length = input_offset - line_start;
        for (key_index = 0; key_index < sizeof(retired_keys) / sizeof(retired_keys[0]); ++key_index) {
            if (config_line_has_key(bytes + line_start, content_length, retired_keys[key_index])) {
                remove_line = TRUE;
                break;
            }
        }
        if (remove_line) {
            *changed = TRUE;
        } else {
            memcpy(result + result_length, bytes + line_start, line_length);
            result_length += line_length;
        }
    }
    *output = result;
    *output_length = result_length;
    return TRUE;
}

static BOOL install_settings(const PatchPaths *paths, BOOL *created, unsigned char **previous_bytes, size_t *previous_length, BOOL *changed) {
    unsigned char *current = NULL;
    unsigned char *migrated = NULL;
    size_t current_length = 0;
    size_t migrated_length = 0;
    unsigned char expected_hash[32];
    unsigned char installed_hash[32];
    *created = FALSE;
    *previous_bytes = NULL;
    *previous_length = 0;
    *changed = FALSE;
    if (path_is_file(paths->settings)) {
        if (!load_entire_file(paths->settings, &current, &current_length) || !strip_retired_settings(current, current_length, &migrated, &migrated_length, changed)) goto failed;
        if (!*changed) {
            free(migrated);
            free(current);
            return TRUE;
        }
        if (!hash_memory(migrated, migrated_length, expected_hash) || !write_file_atomically(paths->settings, migrated, migrated_length) || !hash_file(paths->settings, installed_hash, NULL) || memcmp(installed_hash, expected_hash, 32) != 0) {
            if (!write_file_atomically(paths->settings, current, current_length)) fwprintf(stderr, L"Warning: restoring persistent graphics settings after a failed migration also failed.\n");
            goto failed;
        }
        free(migrated);
        *previous_bytes = current;
        *previous_length = current_length;
        return TRUE;
    }
    if (!hash_memory(k_default_settings, sizeof(k_default_settings) - 1, expected_hash)) return FALSE;
    if (!write_file_atomically(paths->settings, k_default_settings, sizeof(k_default_settings) - 1)) return FALSE;
    if (!hash_file(paths->settings, installed_hash, NULL) || memcmp(installed_hash, expected_hash, 32) != 0) {
        DeleteFileW(paths->settings);
        SetLastError(ERROR_CRC);
        return FALSE;
    }
    *created = TRUE;
    return TRUE;
failed:
    free(migrated);
    free(current);
    *changed = FALSE;
    return FALSE;
}

static BOOL install_patch(const PatchPaths *paths, const Preflight *preflight) {
    BOOL created_native = FALSE;
    BOOL upgraded_native = FALSE;
    BOOL created_script = FALSE;
    BOOL upgraded_script = FALSE;
    BOOL created_settings = FALSE;
    BOOL changed_settings = FALSE;
    BOOL created_parity = FALSE;
    BOOL changed_default = FALSE;
    BOOL changed_install_info = FALSE;
    BOOL changed_udk = FALSE;
    unsigned char *previous_native = NULL;
    unsigned char *previous_script = NULL;
    unsigned char *previous_settings = NULL;
    unsigned char *previous_install_info = NULL;
    size_t previous_native_length = 0;
    size_t previous_script_length = 0;
    size_t previous_settings_length = 0;
    size_t previous_install_info_length = 0;
    unsigned char default_settings_hash[32];
    unsigned char parity_file_hash[32];
    unsigned char retired_proxy_hash[32];
    if (!preflight->accepted_install_record) {
        fwprintf(stderr, L"An accepted UDK 3 record for this game directory was not found. The executable safeguard is only installed after prior acceptance.\n");
        return FALSE;
    }
    if (!ensure_udk_parity(paths, &created_parity, parity_file_hash)) {
        print_last_error(L"Creating or validating 1 MiB UDK recovery parity", paths->udk_parity);
        goto rollback;
    }
    if (!ensure_directory(paths->user_code_directory)) {
        print_last_error(L"Creating UserCode directory", paths->user_code_directory);
        goto rollback;
    }
    if (preflight->native_bridge == FILE_STATE_PREVIOUS) {
        if (!upgrade_payload_file(paths->native_bridge, k_payload_native, k_payload_native_size, preflight->native_hash, hash_matches_previous_native, &previous_native, &previous_native_length)) {
            print_last_error(L"Upgrading runtime display detector", paths->native_bridge);
            goto rollback;
        }
        upgraded_native = TRUE;
    } else {
        if (!install_payload_file(paths->native_bridge, k_payload_native, k_payload_native_size, preflight->native_hash, preflight->native_bridge, &created_native)) {
            print_last_error(L"Installing runtime display detector", paths->native_bridge);
            goto rollback;
        }
    }
    if (preflight->script_package == FILE_STATE_PREVIOUS) {
        if (!upgrade_payload_file(paths->script_package, k_payload_script, k_payload_script_size, preflight->script_hash, hash_matches_previous_script, &previous_script, &previous_script_length)) {
            print_last_error(L"Upgrading in-world menu package", paths->script_package);
            goto rollback;
        }
        upgraded_script = TRUE;
    } else {
        if (!install_payload_file(paths->script_package, k_payload_script, k_payload_script_size, preflight->script_hash, preflight->script_package, &created_script)) {
            print_last_error(L"Installing in-world menu package", paths->script_package);
            goto rollback;
        }
    }
    if (!install_settings(paths, &created_settings, &previous_settings, &previous_settings_length, &changed_settings)) {
        print_last_error(L"Creating or migrating persistent graphics settings", paths->settings);
        goto rollback;
    }
    if (preflight->default_engine == FILE_STATE_ORIGINAL || preflight->default_engine == FILE_STATE_PREVIOUS) {
        if (!patch_default_engine(paths)) goto rollback;
        changed_default = TRUE;
    }
    if (!repair_install_info(paths, preflight->accepted_guid, &previous_install_info, &previous_install_info_length, &changed_install_info)) {
        print_last_error(L"Repairing InstallInfo.xml", paths->install_info);
        goto rollback;
    }
    if (preflight->udk_exe == FILE_STATE_ORIGINAL) {
        if (!patch_udk_exe(paths)) goto rollback;
        changed_udk = TRUE;
    }
    if (preflight->retired_proxy == FILE_STATE_PREVIOUS) {
        if (!hash_file(paths->retired_proxy, retired_proxy_hash, NULL) || !hash_matches_retired_proxy(retired_proxy_hash) || !move_payload_recoverably(paths->retired_proxy, retired_proxy_hash)) {
            print_last_error(L"Retiring the previous d3d9.dll", paths->retired_proxy);
            goto rollback;
        }
    }
    free(previous_install_info);
    free(previous_native);
    free(previous_script);
    free(previous_settings);
    return TRUE;
rollback:
    fwprintf(stderr, L"\nInstallation did not complete; rolling back changes from this run.\n");
    if (changed_udk && !restore_udk_exe(paths)) fwprintf(stderr, L"Warning: automatic rollback failed for UDK.exe.\n");
    if (changed_install_info && !restore_install_info(paths, previous_install_info, previous_install_info_length)) fwprintf(stderr, L"Warning: automatic rollback failed for InstallInfo.xml.\n");
    if (changed_default && !restore_default_engine(paths)) fwprintf(stderr, L"Warning: automatic rollback failed for DefaultEngine.ini.\n");
    if (upgraded_script && !restore_upgraded_payload(paths->script_package, preflight->script_hash, hash_matches_previous_script, previous_script, previous_script_length)) fwprintf(stderr, L"Warning: automatic rollback failed for the previous menu package.\n");
    if (created_script && !delete_if_hash_matches(paths->script_package, preflight->script_hash)) fwprintf(stderr, L"Warning: automatic rollback failed for the menu package.\n");
    if (upgraded_native && !restore_upgraded_payload(paths->native_bridge, preflight->native_hash, hash_matches_previous_native, previous_native, previous_native_length)) fwprintf(stderr, L"Warning: automatic rollback failed for the previous runtime detector.\n");
    if (created_native && !delete_if_hash_matches(paths->native_bridge, preflight->native_hash)) fwprintf(stderr, L"Warning: automatic rollback failed for the runtime detector.\n");
    if (changed_settings && !write_file_atomically(paths->settings, previous_settings, previous_settings_length)) fwprintf(stderr, L"Warning: automatic rollback failed for persistent graphics settings.\n");
    if (created_settings) {
        if (hash_memory(k_default_settings, sizeof(k_default_settings) - 1, default_settings_hash) && !delete_if_hash_matches(paths->settings, default_settings_hash)) fwprintf(stderr, L"Warning: automatic rollback retained UDKAntichamberGraphics.ini.\n");
    }
    if (created_parity && !delete_if_hash_matches(paths->udk_parity, parity_file_hash)) fwprintf(stderr, L"Warning: automatic rollback retained UDK recovery parity.\n");
    free(previous_install_info);
    free(previous_native);
    free(previous_script);
    free(previous_settings);
    return FALSE;
}

static BOOL remove_patch(const PatchPaths *paths, const Preflight *preflight, BOOL use_parity_recovery) {
    BOOL success = TRUE;
    unsigned char retired_proxy_hash[32];
    unsigned char previous_native_hash[32];
    unsigned char previous_script_hash[32];
    const unsigned char *installed_native_hash = preflight->native_hash;
    const unsigned char *installed_script_hash = preflight->script_hash;
    if (preflight->retired_proxy == FILE_STATE_PREVIOUS) {
        if (!hash_file(paths->retired_proxy, retired_proxy_hash, NULL) || !hash_matches_retired_proxy(retired_proxy_hash)) return FALSE;
    }
    if (preflight->script_package == FILE_STATE_PREVIOUS) {
        if (!hash_file(paths->script_package, previous_script_hash, NULL) || !hash_matches_previous_script(previous_script_hash)) return FALSE;
        installed_script_hash = previous_script_hash;
    }
    if (preflight->native_bridge == FILE_STATE_PREVIOUS) {
        if (!hash_file(paths->native_bridge, previous_native_hash, NULL) || !hash_matches_previous_native(previous_native_hash)) return FALSE;
        installed_native_hash = previous_native_hash;
    }
    BOOL restored_default = FALSE;
    if ((preflight->default_engine == FILE_STATE_PATCHED || preflight->default_engine == FILE_STATE_PREVIOUS) && !restore_default_engine(paths)) {
        fwprintf(stderr, L"Could not restore the verified original DefaultEngine.ini. No payloads were removed.\n");
        return FALSE;
    }
    restored_default = preflight->default_engine == FILE_STATE_PATCHED || preflight->default_engine == FILE_STATE_PREVIOUS;
    if ((preflight->udk_exe == FILE_STATE_PATCHED || preflight->udk_exe == FILE_STATE_RECOVERABLE) && !(use_parity_recovery ? restore_udk_exe_with_parity(paths) : restore_udk_exe(paths))) {
        fwprintf(stderr, L"Could not restore UDK.exe to its verified target hash. No payloads were removed.\n");
        if (restored_default && !patch_default_engine(paths)) fwprintf(stderr, L"Warning: reapplying DefaultEngine.ini after the failed removal also failed.\n");
        return FALSE;
    }
    if (!move_payload_recoverably(paths->script_package, installed_script_hash)) {
        print_last_error(L"Removing in-world menu package", paths->script_package);
        success = FALSE;
    }
    if (!move_payload_recoverably(paths->native_bridge, installed_native_hash)) {
        print_last_error(L"Removing runtime display detector", paths->native_bridge);
        success = FALSE;
    }
    if (preflight->retired_proxy == FILE_STATE_PREVIOUS && !move_payload_recoverably(paths->retired_proxy, retired_proxy_hash)) {
        print_last_error(L"Removing the retired d3d9.dll", paths->retired_proxy);
        success = FALSE;
    }
    return success;
}

static void print_usage(const wchar_t *program) {
    wprintf(L"Antichamber Graphics Patch %ls\n\n", PATCH_VERSION);
    wprintf(L"Usage:\n  %ls <game directory> [--install | --check | --unpatch | --remove]\n\n", program);
    wprintf(L"The default action is --install. --unpatch requires verified 1 MiB parity recovery.\n");
    wprintf(L"Close Antichamber before installing, unpatching, or removing.\n");
}

int wmain(int argument_count, wchar_t **arguments) {
    PatchPaths paths;
    Preflight preflight;
    const wchar_t *action = L"--install";
    BOOL use_parity_recovery;
    BOOL compatible;
    if (argument_count < 2 || argument_count > 3 || wcscmp(arguments[1], L"--help") == 0 || wcscmp(arguments[1], L"-h") == 0) {
        print_usage(arguments[0]);
        return argument_count >= 2 ? 0 : 2;
    }
    if (argument_count == 3) action = arguments[2];
    if (wcscmp(action, L"--install") != 0 && wcscmp(action, L"--check") != 0 && wcscmp(action, L"--unpatch") != 0 && wcscmp(action, L"--remove") != 0) {
        fwprintf(stderr, L"Unknown action: %ls\n", action);
        print_usage(arguments[0]);
        return 2;
    }
    if (!initialize_paths(arguments[1], &paths)) {
        fwprintf(stderr, L"That directory does not contain the expected Antichamber layout:\n  %ls\n", arguments[1]);
        return 2;
    }
    wprintf(L"Antichamber Graphics Patch %ls\n", PATCH_VERSION);
    wprintf(L"Game directory:\n  %ls\n\n", paths.root);
    use_parity_recovery = wcscmp(action, L"--unpatch") == 0;
    compatible = run_preflight(&paths, &preflight, TRUE, use_parity_recovery);
    if (!compatible) {
        if (use_parity_recovery) fwprintf(stderr, L"\nNo changes were made. Parity cannot reconstruct UDK.exe to the target hash, or another required file is unsupported.\n");
        else fwprintf(stderr, L"\nNo changes were made. One or more required hashes are not supported by this patch.\n");
        return 3;
    }
    if (wcscmp(action, L"--check") == 0) {
        return 0;
    }
    if (game_is_running()) {
        fwprintf(stderr, L"\nAntichamber/UDK is running. Close it before installing, unpatching, or removing the patch.\n");
        return 4;
    }
    if (wcscmp(action, L"--remove") == 0 || use_parity_recovery) return remove_patch(&paths, &preflight, use_parity_recovery) ? 0 : 1;
    return install_patch(&paths, &preflight) ? 0 : 1;
}
