#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <mutex>
#include <regex>
#include <openssl/evp.h>

#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#include <windows.h>
#else
#define EXPORT extern "C"
#endif

// ============================================================================
// 상수 및 전역 변수
// ============================================================================
static const long MAX_FILE_SIZE = 100 * 1024 * 1024;
static char g_result_buffer[16384];
static std::mutex g_mutex;

// ============================================================================
// PE 구조체
// ============================================================================
#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;
    uint8_t  e_cblp[58];
    uint32_t e_lfanew;
};

struct PEHeader {
    uint32_t signature;
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

struct OptionalHeader32 {
    uint16_t magic;
    uint8_t  majorLinkerVersion;
    uint8_t  minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t addressOfEntryPoint;
    uint32_t baseOfCode;
    uint32_t baseOfData;
    uint32_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checkSum;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint32_t sizeOfStackReserve;
    uint32_t sizeOfStackCommit;
    uint32_t sizeOfHeapReserve;
    uint32_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numberOfRvaAndSizes;
};

struct DataDirectory {
    uint32_t virtualAddress;
    uint32_t size;
};

struct ImportDescriptor {
    uint32_t originalFirstThunk;
    uint32_t timeDateStamp;
    uint32_t forwarderChain;
    uint32_t name;
    uint32_t firstThunk;
};

struct SectionHeader {
    char     name[8];
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLinenumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLinenumbers;
    uint32_t characteristics;
};
#pragma pack(pop)

// ============================================================================
// YARA 룰 구조체
// ============================================================================
struct YaraRule {
    std::string name;
    std::string description;
    std::vector<std::string> strings;      // 문자열 패턴
    std::vector<std::string> hex_patterns; // 헥스 패턴
    std::string condition;                  // 조건 (all, any, N of them)
    int required_matches;                   // 필요한 매치 수
    int severity;
    std::vector<std::string> tags;
};

static std::vector<YaraRule> g_yara_rules = {
    {
        "Ransomware_Generic",
        "Generic ransomware detection",
        {"encrypt", "decrypt", "bitcoin", "ransom", "locked", "payment", "wallet"},
        {"52 61 6E 73 6F 6D"}, // "Ransom"
        "any",
        3,
        4,
        {"ransomware", "malware"}
    },
    {
        "Trojan_Downloader",
        "Trojan downloader detection",
        {"URLDownloadToFile", "WinHttpOpen", "InternetOpen", "download", "execute"},
        {},
        "any",
        2,
        3,
        {"trojan", "downloader"}
    },
    {
        "Keylogger_Generic",
        "Generic keylogger detection",
        {"GetAsyncKeyState", "SetWindowsHookEx", "GetKeyState", "keylog", "keystroke"},
        {},
        "any",
        2,
        3,
        {"keylogger", "spyware"}
    },
    {
        "Backdoor_Generic",
        "Generic backdoor detection",
        {"cmd.exe", "powershell", "reverse", "shell", "connect", "bind"},
        {},
        "any",
        3,
        4,
        {"backdoor", "rat"}
    },
    {
        "Cryptominer",
        "Cryptocurrency miner detection",
        {"stratum", "mining", "hashrate", "xmrig", "monero", "coinhive"},
        {},
        "any",
        2,
        3,
        {"miner", "cryptominer"}
    },
    {
        "Packed_UPX",
        "UPX packed executable",
        {},
        {"55 50 58 30", "55 50 58 31", "55 50 58 21"}, // UPX0, UPX1, UPX!
        "any",
        1,
        2,
        {"packed", "upx"}
    },
    {
        "Suspicious_Injection",
        "Process injection techniques",
        {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx"},
        {},
        "any",
        2,
        4,
        {"injection", "malware"}
    },
    {
        "EICAR_Test",
        "EICAR test file",
        {"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"},
        {},
        "any",
        1,
        1,
        {"test", "eicar"}
    }
};

// ============================================================================
// 의심스러운 Import API 목록
// ============================================================================
struct SuspiciousAPI {
    std::string name;
    std::string category;
    int risk_score;
};

static std::vector<SuspiciousAPI> g_suspicious_apis = {
    // 프로세스 인젝션
    {"VirtualAllocEx", "injection", 8},
    {"WriteProcessMemory", "injection", 9},
    {"CreateRemoteThread", "injection", 10},
    {"NtCreateThreadEx", "injection", 10},
    {"QueueUserAPC", "injection", 7},
    {"SetThreadContext", "injection", 8},

    // 키로깅
    {"GetAsyncKeyState", "keylogger", 7},
    {"SetWindowsHookExA", "keylogger", 8},
    {"SetWindowsHookExW", "keylogger", 8},
    {"GetKeyState", "keylogger", 5},
    {"GetKeyboardState", "keylogger", 6},

    // 네트워크
    {"URLDownloadToFileA", "downloader", 6},
    {"URLDownloadToFileW", "downloader", 6},
    {"InternetOpenA", "network", 3},
    {"InternetOpenUrlA", "network", 4},
    {"WinHttpOpen", "network", 3},
    {"WSAStartup", "network", 2},

    // 파일 시스템
    {"CreateFileA", "file", 1},
    {"DeleteFileA", "file", 3},
    {"MoveFileA", "file", 2},
    {"CopyFileA", "file", 2},

    // 레지스트리
    {"RegSetValueExA", "registry", 4},
    {"RegCreateKeyExA", "registry", 3},
    {"RegDeleteKeyA", "registry", 5},

    // 권한 상승
    {"AdjustTokenPrivileges", "privilege", 7},
    {"OpenProcessToken", "privilege", 5},
    {"LookupPrivilegeValueA", "privilege", 4},

    // 안티 디버깅
    {"IsDebuggerPresent", "antidebug", 6},
    {"CheckRemoteDebuggerPresent", "antidebug", 7},
    {"NtQueryInformationProcess", "antidebug", 5},

    // 암호화
    {"CryptEncrypt", "crypto", 4},
    {"CryptDecrypt", "crypto", 4},
    {"CryptGenKey", "crypto", 3},

    // 서비스
    {"CreateServiceA", "service", 5},
    {"StartServiceA", "service", 4},
    {"OpenSCManagerA", "service", 3},

    // 셸 실행
    {"ShellExecuteA", "execution", 5},
    {"ShellExecuteExA", "execution", 5},
    {"CreateProcessA", "execution", 4},
    {"WinExec", "execution", 6},
    {"system", "execution", 7},
};

// ============================================================================
// 시그니처 및 해시 DB
// ============================================================================
struct SignaturePattern {
    std::string name;
    std::string pattern;
    int severity;
    int min_occurrences;
    bool require_pe;
};

struct HashEntry {
    std::string hash;
    std::string threat_name;
    int severity;
};

static std::vector<SignaturePattern> g_signatures = {
    {"Generic.Malware", "malware_payload", 3, 1, false},
    {"Generic.Virus", "virus_infect", 3, 1, false},
    {"Trojan.Generic", "trojan_download", 4, 1, false},
};

static std::vector<HashEntry> g_bad_md5 = {
    {"098f6bcd4621d373cade4e832627b4f6", "Test.Malware", 1},
};

static std::vector<HashEntry> g_bad_sha256 = {};

// ============================================================================
// 화이트리스트
// ============================================================================
static std::vector<std::string> g_whitelist_hashes;
static std::vector<std::wstring> g_whitelist_paths = {
    L"C:\\Windows\\System32\\",
    L"C:\\Windows\\SysWOW64\\",
    L"C:\\Program Files\\",
    L"C:\\Program Files (x86)\\",
};

static std::set<std::wstring> g_safe_ext = {
    L".txt", L".log", L".md", L".json", L".xml", L".csv",
    L".jpg", L".jpeg", L".png", L".gif", L".bmp",
    L".mp3", L".mp4", L".avi", L".mkv",
    L".pdf", L".doc", L".docx", L".xls", L".xlsx",
};

static std::set<std::wstring> g_dangerous_ext = {
    L".exe", L".dll", L".sys", L".scr", L".bat", L".cmd",
    L".ps1", L".vbs", L".js", L".msi", L".hta",
};

// ============================================================================
// 유틸리티 함수
// ============================================================================
static std::wstring get_ext(const wchar_t* p) {
    if (!p) return L"";
    std::wstring s(p);
    size_t pos = s.rfind(L'.');
    if (pos == std::wstring::npos) return L"";
    std::wstring e = s.substr(pos);
    for (auto& c : e) c = towlower(c);
    return e;
}

static bool is_safe_ext(const wchar_t* p) { return g_safe_ext.count(get_ext(p)) > 0; }
static bool is_dangerous_ext(const wchar_t* p) { return g_dangerous_ext.count(get_ext(p)) > 0; }

static std::string read_file(const wchar_t* path, long* sz) {
    if (!path || !path[0]) { if (sz) *sz = 0; return ""; }
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f) { if (sz) *sz = 0; return ""; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) { fclose(f); if (sz) *sz = 0; return ""; }
    if (sz) *sz = size;
    if (size > MAX_FILE_SIZE) size = MAX_FILE_SIZE;
    std::string data;
    try { data.resize(size); fread(&data[0], 1, size, f); }
    catch (...) { fclose(f); return ""; }
    fclose(f);
    return data;
}

static std::string calc_md5(const std::string& d) {
    const char* zero_md5 = "00000000000000000000000000000000";
    if (d.empty()) return zero_md5;

    try {
        unsigned char dig[16];
        memset(dig, 0, sizeof(dig));

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return zero_md5;

        const EVP_MD* md = EVP_md5();
        if (!md) {
            EVP_MD_CTX_free(ctx);
            return zero_md5;
        }

        int ok = 1;
        ok = ok && (EVP_DigestInit_ex(ctx, md, NULL) == 1);
        ok = ok && (EVP_DigestUpdate(ctx, d.data(), d.size()) == 1);

        unsigned int len = 0;
        ok = ok && (EVP_DigestFinal_ex(ctx, dig, &len) == 1);

        EVP_MD_CTX_free(ctx);

        if (!ok || len != 16) return zero_md5;

        char buf[33];
        for (int i = 0; i < 16; i++) {
            buf[i*2] = "0123456789abcdef"[dig[i] >> 4];
            buf[i*2+1] = "0123456789abcdef"[dig[i] & 0x0f];
        }
        buf[32] = '\0';
        return std::string(buf);
    } catch (...) {
        return zero_md5;
    }
}

static std::string calc_sha256(const std::string& d) {
    const char* zero_sha = "0000000000000000000000000000000000000000000000000000000000000000";
    if (d.empty()) return zero_sha;

    try {
        unsigned char dig[32];
        memset(dig, 0, sizeof(dig));

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return zero_sha;

        const EVP_MD* md = EVP_sha256();
        if (!md) {
            EVP_MD_CTX_free(ctx);
            return zero_sha;
        }

        int ok = 1;
        ok = ok && (EVP_DigestInit_ex(ctx, md, NULL) == 1);
        ok = ok && (EVP_DigestUpdate(ctx, d.data(), d.size()) == 1);

        unsigned int len = 0;
        ok = ok && (EVP_DigestFinal_ex(ctx, dig, &len) == 1);

        EVP_MD_CTX_free(ctx);

        if (!ok || len != 32) return zero_sha;

        char buf[65];
        for (int i = 0; i < 32; i++) {
            buf[i*2] = "0123456789abcdef"[dig[i] >> 4];
            buf[i*2+1] = "0123456789abcdef"[dig[i] & 0x0f];
        }
        buf[64] = '\0';
        return std::string(buf);
    } catch (...) {
        return zero_sha;
    }
}

static double calc_entropy(const std::string& d) {
    if (d.empty()) return 0.0;
    int freq[256] = {0};
    for (unsigned char c : d) freq[c]++;
    double ent = 0.0, len = (double)d.size();
    for (int i = 0; i < 256; i++)
        if (freq[i] > 0) { double p = freq[i]/len; ent -= p * log2(p); }
    return ent;
}


// ============================================================================
// YARA 룰 엔진
// ============================================================================
struct YaraMatchResult {
    bool matched;
    std::string rule_name;
    std::string description;
    int severity;
    int match_count;
    std::vector<std::string> matched_strings;
};

static bool match_hex_pattern(const std::string& data, const std::string& hex_pattern) {
    // 헥스 패턴을 바이트로 변환하여 검색
    std::string bytes;
    std::istringstream iss(hex_pattern);
    std::string byte;
    while (iss >> byte) {
        if (byte == "??") {
            bytes += '\x00'; // 와일드카드는 일단 스킵
            continue;
        }
        try {
            bytes += (char)std::stoi(byte, nullptr, 16);
        } catch (...) {}
    }
    return data.find(bytes) != std::string::npos;
}

static YaraMatchResult check_yara_rules(const std::string& data) {
    YaraMatchResult result = {false, "", "", 0, 0, {}};

    std::string lower = data;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    for (const auto& rule : g_yara_rules) {
        int matches = 0;
        std::vector<std::string> matched;

        // 문자열 패턴 검사
        for (const auto& str : rule.strings) {
            std::string str_lower = str;
            std::transform(str_lower.begin(), str_lower.end(), str_lower.begin(), ::tolower);
            if (lower.find(str_lower) != std::string::npos) {
                matches++;
                matched.push_back(str);
            }
        }

        // 헥스 패턴 검사
        for (const auto& hex : rule.hex_patterns) {
            if (match_hex_pattern(data, hex)) {
                matches++;
                matched.push_back("[HEX]" + hex);
            }
        }

        // 조건 확인
        bool rule_matched = false;
        if (rule.condition == "all") {
            rule_matched = (matches == (int)(rule.strings.size() + rule.hex_patterns.size()));
        } else if (rule.condition == "any") {
            rule_matched = (matches >= rule.required_matches);
        } else {
            rule_matched = (matches >= rule.required_matches);
        }

        if (rule_matched && matches > result.match_count) {
            result.matched = true;
            result.rule_name = rule.name;
            result.description = rule.description;
            result.severity = rule.severity;
            result.match_count = matches;
            result.matched_strings = matched;
        }
    }

    return result;
}

// ============================================================================
// Import Table 분석
// ============================================================================
struct ImportAnalysisResult {
    bool success;
    std::vector<std::string> dlls;
    std::vector<std::string> functions;
    std::vector<std::string> suspicious_apis;
    int risk_score;
    std::string risk_category;
};

static uint32_t rva_to_offset(uint32_t rva, const std::vector<SectionHeader>& sections) {
    for (const auto& sec : sections) {
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
            return rva - sec.virtualAddress + sec.pointerToRawData;
        }
    }
    return 0;
}

static ImportAnalysisResult analyze_imports(const std::string& data) {
    ImportAnalysisResult result = {false, {}, {}, {}, 0, ""};

    if (data.size() < sizeof(DOSHeader)) return result;

    const DOSHeader* dos = (const DOSHeader*)data.data();
    if (dos->e_magic != 0x5A4D) return result;

    if (data.size() < dos->e_lfanew + sizeof(PEHeader)) return result;

    const PEHeader* pe = (const PEHeader*)(data.data() + dos->e_lfanew);
    if (pe->signature != 0x00004550) return result;

    // Optional Header
    size_t opt_offset = dos->e_lfanew + sizeof(PEHeader);
    if (data.size() < opt_offset + sizeof(OptionalHeader32)) return result;

    const OptionalHeader32* opt = (const OptionalHeader32*)(data.data() + opt_offset);

    // 섹션 헤더 읽기
    std::vector<SectionHeader> sections;
    size_t sec_offset = opt_offset + pe->sizeOfOptionalHeader;
    for (int i = 0; i < pe->numberOfSections && i < 96; i++) {
        if (data.size() < sec_offset + sizeof(SectionHeader)) break;
        sections.push_back(*(const SectionHeader*)(data.data() + sec_offset));
        sec_offset += sizeof(SectionHeader);
    }

    // Import Directory (Data Directory[1])
    size_t dd_offset = opt_offset + offsetof(OptionalHeader32, numberOfRvaAndSizes) + 4;
    if (data.size() < dd_offset + 2 * sizeof(DataDirectory)) return result;

    const DataDirectory* import_dir = (const DataDirectory*)(data.data() + dd_offset + sizeof(DataDirectory));

    if (import_dir->virtualAddress == 0 || import_dir->size == 0) {
        result.success = true;
        return result;
    }

    uint32_t import_offset = rva_to_offset(import_dir->virtualAddress, sections);
    if (import_offset == 0 || import_offset >= data.size()) {
        result.success = true;
        return result;
    }

    // Import Descriptor 순회
    std::map<std::string, int> category_scores;

    for (size_t i = 0; i < 256; i++) {
        size_t desc_offset = import_offset + i * sizeof(ImportDescriptor);
        if (desc_offset + sizeof(ImportDescriptor) > data.size()) break;

        const ImportDescriptor* desc = (const ImportDescriptor*)(data.data() + desc_offset);
        if (desc->name == 0) break;

        uint32_t name_offset = rva_to_offset(desc->name, sections);
        if (name_offset == 0 || name_offset >= data.size()) continue;

        std::string dll_name;
        for (size_t j = 0; j < 256 && name_offset + j < data.size(); j++) {
            char c = data[name_offset + j];
            if (c == 0) break;
            dll_name += c;
        }

        if (!dll_name.empty()) {
            result.dlls.push_back(dll_name);
        }

        // Import Name Table 순회
        uint32_t thunk_rva = desc->originalFirstThunk ? desc->originalFirstThunk : desc->firstThunk;
        uint32_t thunk_offset = rva_to_offset(thunk_rva, sections);
        if (thunk_offset == 0) continue;

        for (size_t j = 0; j < 1024; j++) {
            size_t entry_offset = thunk_offset + j * 4;
            if (entry_offset + 4 > data.size()) break;

            uint32_t entry = *(const uint32_t*)(data.data() + entry_offset);
            if (entry == 0) break;

            if (entry & 0x80000000) continue; // Ordinal import

            uint32_t hint_offset = rva_to_offset(entry, sections);
            if (hint_offset == 0 || hint_offset + 2 >= data.size()) continue;

            std::string func_name;
            for (size_t k = 0; k < 256 && hint_offset + 2 + k < data.size(); k++) {
                char c = data[hint_offset + 2 + k];
                if (c == 0) break;
                func_name += c;
            }

            if (!func_name.empty()) {
                result.functions.push_back(func_name);

                // 의심스러운 API 확인
                for (const auto& api : g_suspicious_apis) {
                    if (func_name == api.name) {
                        result.suspicious_apis.push_back(func_name + " (" + api.category + ")");
                        result.risk_score += api.risk_score;
                        category_scores[api.category] += api.risk_score;
                    }
                }
            }
        }
    }

    // 가장 위험한 카테고리 찾기
    int max_score = 0;
    for (const auto& cat : category_scores) {
        if (cat.second > max_score) {
            max_score = cat.second;
            result.risk_category = cat.first;
        }
    }

    result.success = true;
    return result;
}

// ============================================================================
// PE 분석
// ============================================================================
struct PEAnalysisResult {
    bool is_pe;
    bool is_suspicious;
    bool is_packed;
    bool is_64bit;
    int section_count;
    std::string details;
    std::vector<std::string> sections;
    uint32_t entry_point;
    uint32_t timestamp;
};

static PEAnalysisResult analyze_pe(const std::string& data) {
    PEAnalysisResult result = {false, false, false, false, 0, "", {}, 0, 0};

    if (data.size() < sizeof(DOSHeader)) return result;

    const DOSHeader* dos = (const DOSHeader*)data.data();
    if (dos->e_magic != 0x5A4D) return result;

    result.is_pe = true;

    if (data.size() < dos->e_lfanew + sizeof(PEHeader)) return result;

    const PEHeader* pe = (const PEHeader*)(data.data() + dos->e_lfanew);
    if (pe->signature != 0x00004550) {
        result.is_pe = false;
        return result;
    }

    result.section_count = pe->numberOfSections;
    result.timestamp = pe->timeDateStamp;
    result.is_64bit = (pe->machine == 0x8664);

    // Optional Header에서 Entry Point
    size_t opt_offset = dos->e_lfanew + sizeof(PEHeader);
    if (data.size() >= opt_offset + 20) {
        result.entry_point = *(const uint32_t*)(data.data() + opt_offset + 16);
    }

    // 섹션 분석
    size_t sec_offset = opt_offset + pe->sizeOfOptionalHeader;
    for (int i = 0; i < pe->numberOfSections && i < 96; i++) {
        if (data.size() < sec_offset + sizeof(SectionHeader)) break;

        const SectionHeader* sec = (const SectionHeader*)(data.data() + sec_offset);
        std::string name(sec->name, strnlen(sec->name, 8));
        result.sections.push_back(name);

        // 패킹 탐지
        if (name.find("UPX") != std::string::npos ||
            name.find("ASPack") != std::string::npos ||
            name.find(".nsp") != std::string::npos ||
            name.find("themida") != std::string::npos) {
            result.is_packed = true;
            result.details += "Packed(" + name + "); ";
        }

        // 실행+쓰기 가능 섹션
        if ((sec->characteristics & 0x20000000) && (sec->characteristics & 0x80000000)) {
            result.is_suspicious = true;
            result.details += "WX(" + name + "); ";
        }

        // 비정상적인 섹션 이름
        if (name[0] == '.' && !isalpha(name[1]) && name[1] != 0) {
            result.is_suspicious = true;
            result.details += "BadName(" + name + "); ";
        }

        sec_offset += sizeof(SectionHeader);
    }

    // 엔트로피 기반 패킹 탐지
    double ent = calc_entropy(data);
    if (ent > 7.2) {
        result.is_packed = true;
        result.details += "HighEntropy; ";
    }

    return result;
}


// ============================================================================
// 압축 파일 검사 (ZIP)
// ============================================================================
struct ZipEntry {
    std::string filename;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    bool is_encrypted;
};

struct ZipAnalysisResult {
    bool is_zip;
    std::vector<ZipEntry> entries;
    bool has_executable;
    bool has_suspicious;
    std::string suspicious_file;
};

static ZipAnalysisResult analyze_zip(const std::string& data) {
    ZipAnalysisResult result = {false, {}, false, false, ""};

    // ZIP 시그니처 확인 (PK..)
    if (data.size() < 4) return result;
    if (data[0] != 'P' || data[1] != 'K') return result;

    result.is_zip = true;

    // Local File Header 순회
    size_t offset = 0;
    while (offset + 30 < data.size()) {
        // Local file header signature
        if (data[offset] != 'P' || data[offset+1] != 'K' ||
            data[offset+2] != 0x03 || data[offset+3] != 0x04) {
            break;
        }

        uint16_t flags = *(const uint16_t*)(data.data() + offset + 6);
        uint32_t comp_size = *(const uint32_t*)(data.data() + offset + 18);
        uint32_t uncomp_size = *(const uint32_t*)(data.data() + offset + 22);
        uint16_t name_len = *(const uint16_t*)(data.data() + offset + 26);
        uint16_t extra_len = *(const uint16_t*)(data.data() + offset + 28);

        if (offset + 30 + name_len > data.size()) break;

        std::string filename(data.data() + offset + 30, name_len);

        ZipEntry entry;
        entry.filename = filename;
        entry.compressed_size = comp_size;
        entry.uncompressed_size = uncomp_size;
        entry.is_encrypted = (flags & 0x01) != 0;
        result.entries.push_back(entry);

        // 위험한 파일 확인
        std::string lower = filename;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower.find(".exe") != std::string::npos ||
            lower.find(".dll") != std::string::npos ||
            lower.find(".scr") != std::string::npos ||
            lower.find(".bat") != std::string::npos ||
            lower.find(".cmd") != std::string::npos ||
            lower.find(".ps1") != std::string::npos ||
            lower.find(".vbs") != std::string::npos) {
            result.has_executable = true;
            result.suspicious_file = filename;
        }

        // 이중 확장자 탐지
        if ((lower.find(".pdf.exe") != std::string::npos) ||
            (lower.find(".doc.exe") != std::string::npos) ||
            (lower.find(".jpg.exe") != std::string::npos) ||
            (lower.find(".txt.exe") != std::string::npos)) {
            result.has_suspicious = true;
            result.suspicious_file = filename;
        }

        offset += 30 + name_len + extra_len + comp_size;
    }

    return result;
}

// ============================================================================
// 시그니처/해시 검사
// ============================================================================
static bool check_signatures(const std::string& data, std::string& name, bool is_pe, bool dangerous) {
    std::string lower = data;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    for (const auto& sig : g_signatures) {
        if (sig.require_pe && !is_pe) continue;
        std::string pat = sig.pattern;
        std::transform(pat.begin(), pat.end(), pat.begin(), ::tolower);
        if (lower.find(pat) != std::string::npos) {
            if (!dangerous && sig.severity <= 2) continue;
            name = sig.name;
            return true;
        }
    }
    return false;
}

static bool check_hashes(const std::string& md5, const std::string& sha256, std::string& name) {
    for (const auto& h : g_bad_md5) {
        if (h.hash == md5) { name = h.threat_name; return true; }
    }
    for (const auto& h : g_bad_sha256) {
        if (h.hash == sha256) { name = h.threat_name; return true; }
    }
    return false;
}

// ============================================================================
// DLL 엔트리
// ============================================================================
#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    return TRUE;
}
#endif

// ============================================================================
// 내보내기 함수들
// ============================================================================

EXPORT int scan_file(const wchar_t* filepath) {
    if (!filepath || !filepath[0]) return -1;
    if (is_safe_ext(filepath)) return 0;

    long size = 0;
    std::string data = read_file(filepath, &size);
    if (data.empty() || size < 100) return (size > 0) ? 0 : -1;

    std::string md5 = calc_md5(data);
    std::string sha256 = calc_sha256(data);

    // 화이트리스트
    for (const auto& h : g_whitelist_hashes)
        if (h == md5 || h == sha256) return 0;

    PEAnalysisResult pe = analyze_pe(data);
    bool dangerous = is_dangerous_ext(filepath);
    std::string threat;

    // YARA 룰 검사
    YaraMatchResult yara = check_yara_rules(data);
    if (yara.matched && yara.severity >= 3) return 1;

    // 시그니처 검사
    if (check_signatures(data, threat, pe.is_pe, dangerous)) return 1;

    // 해시 검사
    if (check_hashes(md5, sha256, threat)) return 2;

    // Import 분석
    if (pe.is_pe) {
        ImportAnalysisResult imp = analyze_imports(data);
        if (imp.risk_score >= 30) return 3;
    }

    // ZIP 검사
    ZipAnalysisResult zip = analyze_zip(data);
    if (zip.is_zip && zip.has_suspicious) return 3;

    return 0;
}

EXPORT const char* scan_file_detailed(const wchar_t* filepath) {
    // 버퍼 초기화
    memset(g_result_buffer, 0, sizeof(g_result_buffer));

    // NULL 체크
    if (!filepath) {
        strcpy(g_result_buffer, "{\"status\":-1,\"threat_type\":\"error\",\"threat_name\":\"NULL\",\"md5\":\"\",\"sha256\":\"\",\"entropy\":0,\"file_size\":0}");
        return g_result_buffer;
    }

    // 빈 문자열 체크
    if (filepath[0] == L'\0') {
        strcpy(g_result_buffer, "{\"status\":-1,\"threat_type\":\"error\",\"threat_name\":\"Empty\",\"md5\":\"\",\"sha256\":\"\",\"entropy\":0,\"file_size\":0}");
        return g_result_buffer;
    }

    // 파일 읽기
    long size = 0;
    std::string data;

    FILE* f = nullptr;
    if (_wfopen_s(&f, filepath, L"rb") != 0 || !f) {
        strcpy(g_result_buffer, "{\"status\":-1,\"threat_type\":\"error\",\"threat_name\":\"OpenFail\",\"md5\":\"\",\"sha256\":\"\",\"entropy\":0,\"file_size\":0}");
        return g_result_buffer;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > MAX_FILE_SIZE) {
        fclose(f);
        snprintf(g_result_buffer, sizeof(g_result_buffer)-1,
            "{\"status\":0,\"threat_type\":\"none\",\"threat_name\":\"Clean\",\"md5\":\"\",\"sha256\":\"\",\"entropy\":0,\"file_size\":%ld}", size);
        return g_result_buffer;
    }

    data.resize(size);
    size_t read_size = fread(&data[0], 1, size, f);
    fclose(f);

    if (read_size == 0) {
        strcpy(g_result_buffer, "{\"status\":-1,\"threat_type\":\"error\",\"threat_name\":\"ReadFail\",\"md5\":\"\",\"sha256\":\"\",\"entropy\":0,\"file_size\":0}");
        return g_result_buffer;
    }

    // 해시 계산
    std::string md5 = calc_md5(data);
    std::string sha256 = calc_sha256(data);
    double entropy = calc_entropy(data);

    // 기본 결과
    int status = 0;
    const char* threat_type = "none";
    const char* threat_name = "Clean";
    int severity = 0;
    bool is_pe = (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z');
    bool is_packed = false;
    bool is_64bit = false;
    int pe_sections = 0;

    // PE 분석
    if (is_pe && data.size() >= 64) {
        PEAnalysisResult pe = analyze_pe(data);
        is_packed = pe.is_packed;
        is_64bit = pe.is_64bit;
        pe_sections = pe.section_count;

        if (pe.is_packed) {
            status = 3;
            threat_type = "pe";
            threat_name = "Packed";
            severity = 2;
        }
    }

    // YARA 검사
    static char yara_name[64] = {0};
    if (status == 0 && data.size() > 0) {
        YaraMatchResult yara = check_yara_rules(data);
        if (yara.matched) {
            status = 1;
            threat_type = "yara";
            strncpy(yara_name, yara.rule_name.c_str(), 63);
            yara_name[63] = '\0';
            threat_name = yara_name;
            severity = yara.severity;
        }
    }

    // 시그니처 검사
    static char sig_name[64] = {0};
    if (status == 0) {
        std::string sig_threat;
        if (check_signatures(data, sig_threat, is_pe, is_pe)) {
            status = 1;
            threat_type = "signature";
            strncpy(sig_name, sig_threat.c_str(), 63);
            sig_name[63] = '\0';
            threat_name = sig_name;
        }
    }

    // 해시 검사
    static char hash_name[64] = {0};
    if (status == 0) {
        std::string hash_threat;
        if (check_hashes(md5, sha256, hash_threat)) {
            status = 2;
            threat_type = "hash";
            strncpy(hash_name, hash_threat.c_str(), 63);
            hash_name[63] = '\0';
            threat_name = hash_name;
        }
    }

    // 높은 엔트로피
    if (status == 0 && entropy > 7.5 && is_pe) {
        status = 3;
        threat_type = "entropy";
        threat_name = "HighEntropy";
        severity = 2;
    }

    // yara_rule 필드 설정
    const char* yara_rule_out = (strcmp(threat_type, "yara") == 0) ? yara_name : "";

    // JSON 생성
    snprintf(g_result_buffer, sizeof(g_result_buffer) - 1,
        "{\"status\":%d,\"threat_type\":\"%s\",\"threat_name\":\"%s\","
        "\"severity\":%d,\"md5\":\"%s\",\"sha256\":\"%s\",\"entropy\":%.2f,\"file_size\":%ld,"
        "\"is_pe\":%s,\"is_packed\":%s,\"is_64bit\":%s,\"pe_sections\":%d,"
        "\"import_risk_score\":0,\"yara_rule\":\"%s\"}",
        status, threat_type, threat_name,
        severity, md5.c_str(), sha256.c_str(), entropy, size,
        is_pe ? "true" : "false", is_packed ? "true" : "false",
        is_64bit ? "true" : "false", pe_sections, yara_rule_out);

    return g_result_buffer;
}


// ============================================================================
// YARA 룰 관리
// ============================================================================
EXPORT int add_yara_rule(const char* name, const char* desc, const char* strings_json,
                         const char* condition, int required, int severity) {
    if (!name) return -1;
    std::lock_guard<std::mutex> lock(g_mutex);

    YaraRule rule;
    rule.name = name;
    rule.description = desc ? desc : "";
    rule.condition = condition ? condition : "any";
    rule.required_matches = required;
    rule.severity = severity;

    // 간단한 문자열 파싱 (쉼표로 구분)
    if (strings_json) {
        std::string s = strings_json;
        size_t pos = 0;
        while ((pos = s.find(',')) != std::string::npos) {
            std::string token = s.substr(0, pos);
            if (!token.empty()) rule.strings.push_back(token);
            s.erase(0, pos + 1);
        }
        if (!s.empty()) rule.strings.push_back(s);
    }

    g_yara_rules.push_back(rule);
    return (int)g_yara_rules.size();
}

EXPORT int load_yara_rules_from_file(const wchar_t* filepath) {
    // TODO: YARA 파일 파싱 구현
    return 0;
}

// ============================================================================
// Import 분석 API
// ============================================================================
EXPORT const char* analyze_imports_api(const wchar_t* filepath) {
    memset(g_result_buffer, 0, sizeof(g_result_buffer));

    if (!filepath || filepath[0] == L'\0') {
        strcpy(g_result_buffer, "{\"error\":\"Invalid path\"}");
        return g_result_buffer;
    }

    // 파일 읽기
    FILE* f = nullptr;
    if (_wfopen_s(&f, filepath, L"rb") != 0 || !f) {
        strcpy(g_result_buffer, "{\"error\":\"Cannot open\"}");
        return g_result_buffer;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > MAX_FILE_SIZE) {
        fclose(f);
        strcpy(g_result_buffer, "{\"error\":\"Invalid size\"}");
        return g_result_buffer;
    }

    std::string data;
    data.resize(size);
    fread(&data[0], 1, size, f);
    fclose(f);

    ImportAnalysisResult imp = analyze_imports(data);

    // 문자열 버퍼 (static으로 유지)
    static char dlls_buf[2048];
    static char apis_buf[2048];
    dlls_buf[0] = '\0';
    apis_buf[0] = '\0';

    int pos = 0;
    for (size_t i = 0; i < imp.dlls.size() && i < 20 && pos < 2000; i++) {
        if (i > 0) { dlls_buf[pos++] = ','; dlls_buf[pos++] = ' '; }
        strncpy(dlls_buf + pos, imp.dlls[i].c_str(), 2000 - pos);
        pos += (int)imp.dlls[i].length();
    }
    dlls_buf[pos] = '\0';

    pos = 0;
    for (size_t i = 0; i < imp.suspicious_apis.size() && i < 20 && pos < 2000; i++) {
        if (i > 0) { apis_buf[pos++] = ','; apis_buf[pos++] = ' '; }
        strncpy(apis_buf + pos, imp.suspicious_apis[i].c_str(), 2000 - pos);
        pos += (int)imp.suspicious_apis[i].length();
    }
    apis_buf[pos] = '\0';

    static char risk_cat[64];
    strncpy(risk_cat, imp.risk_category.c_str(), 63);
    risk_cat[63] = '\0';

    snprintf(g_result_buffer, sizeof(g_result_buffer) - 1,
        "{\"success\":%s,\"dll_count\":%d,\"function_count\":%d,"
        "\"risk_score\":%d,\"risk_category\":\"%s\","
        "\"dlls\":\"%s\",\"suspicious_apis\":\"%s\"}",
        imp.success ? "true" : "false", (int)imp.dlls.size(), (int)imp.functions.size(),
        imp.risk_score, risk_cat, dlls_buf, apis_buf);

    return g_result_buffer;
}

// ============================================================================
// 압축 파일 분석 API
// ============================================================================
EXPORT const char* analyze_archive(const wchar_t* filepath) {
    memset(g_result_buffer, 0, sizeof(g_result_buffer));

    if (!filepath || filepath[0] == L'\0') {
        strcpy(g_result_buffer, "{\"error\":\"Invalid path\"}");
        return g_result_buffer;
    }

    // 파일 읽기
    FILE* f = nullptr;
    if (_wfopen_s(&f, filepath, L"rb") != 0 || !f) {
        strcpy(g_result_buffer, "{\"error\":\"Cannot open\"}");
        return g_result_buffer;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > MAX_FILE_SIZE) {
        fclose(f);
        strcpy(g_result_buffer, "{\"error\":\"Invalid size\"}");
        return g_result_buffer;
    }

    std::string data;
    data.resize(size);
    fread(&data[0], 1, size, f);
    fclose(f);

    ZipAnalysisResult zip = analyze_zip(data);

    static char files_buf[4096];
    static char suspicious_buf[256];
    files_buf[0] = '\0';
    suspicious_buf[0] = '\0';

    int pos = 0;
    for (size_t i = 0; i < zip.entries.size() && i < 20 && pos < 4000; i++) {
        if (i > 0) { files_buf[pos++] = ','; files_buf[pos++] = ' '; }
        strncpy(files_buf + pos, zip.entries[i].filename.c_str(), 4000 - pos);
        pos += (int)zip.entries[i].filename.length();
    }
    files_buf[pos] = '\0';

    strncpy(suspicious_buf, zip.suspicious_file.c_str(), 255);
    suspicious_buf[255] = '\0';

    snprintf(g_result_buffer, sizeof(g_result_buffer) - 1,
        "{\"is_archive\":%s,\"file_count\":%d,\"has_executable\":%s,"
        "\"has_suspicious\":%s,\"suspicious_file\":\"%s\",\"files\":\"%s\"}",
        zip.is_zip ? "true" : "false", (int)zip.entries.size(),
        zip.has_executable ? "true" : "false", zip.has_suspicious ? "true" : "false",
        suspicious_buf, files_buf);

    return g_result_buffer;
}

// ============================================================================
// PE 분석 API
// ============================================================================
EXPORT const char* analyze_pe_file(const wchar_t* filepath) {
    memset(g_result_buffer, 0, sizeof(g_result_buffer));

    if (!filepath || filepath[0] == L'\0') {
        strcpy(g_result_buffer, "{\"error\":\"Invalid path\"}");
        return g_result_buffer;
    }

    // 파일 읽기
    FILE* f = nullptr;
    if (_wfopen_s(&f, filepath, L"rb") != 0 || !f) {
        strcpy(g_result_buffer, "{\"error\":\"Cannot open\"}");
        return g_result_buffer;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > MAX_FILE_SIZE) {
        fclose(f);
        strcpy(g_result_buffer, "{\"error\":\"Invalid size\"}");
        return g_result_buffer;
    }

    std::string data;
    data.resize(size);
    fread(&data[0], 1, size, f);
    fclose(f);

    PEAnalysisResult pe = analyze_pe(data);

    static char sections_buf[1024];
    static char details_buf[512];
    sections_buf[0] = '\0';
    details_buf[0] = '\0';

    int pos = 0;
    for (size_t i = 0; i < pe.sections.size() && pos < 1000; i++) {
        if (i > 0) { sections_buf[pos++] = ','; sections_buf[pos++] = ' '; }
        strncpy(sections_buf + pos, pe.sections[i].c_str(), 1000 - pos);
        pos += (int)pe.sections[i].length();
    }
    sections_buf[pos] = '\0';

    strncpy(details_buf, pe.details.c_str(), 511);
    details_buf[511] = '\0';

    snprintf(g_result_buffer, sizeof(g_result_buffer) - 1,
        "{\"is_pe\":%s,\"is_64bit\":%s,\"is_packed\":%s,\"is_suspicious\":%s,"
        "\"section_count\":%d,\"entry_point\":%u,\"timestamp\":%u,"
        "\"sections\":\"%s\",\"details\":\"%s\"}",
        pe.is_pe ? "true" : "false", pe.is_64bit ? "true" : "false",
        pe.is_packed ? "true" : "false", pe.is_suspicious ? "true" : "false",
        pe.section_count, pe.entry_point, pe.timestamp,
        sections_buf, details_buf);

    return g_result_buffer;
}

// ============================================================================
// 기존 API
// ============================================================================
EXPORT int add_signature(const char* name, const char* pattern, int severity) {
    if (!name || !pattern) return -1;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_signatures.push_back({name, pattern, severity, 1, false});
    return (int)g_signatures.size();
}

EXPORT int add_hash(const char* hash, const char* name, int severity, bool is_sha256) {
    if (!hash || !name) return -1;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (is_sha256) {
        g_bad_sha256.push_back({hash, name, severity});
        return (int)g_bad_sha256.size();
    } else {
        g_bad_md5.push_back({hash, name, severity});
        return (int)g_bad_md5.size();
    }
}

EXPORT int add_whitelist_hash(const char* hash) {
    if (!hash) return -1;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_whitelist_hashes.push_back(hash);
    return (int)g_whitelist_hashes.size();
}

EXPORT int add_whitelist_path(const wchar_t* path) {
    if (!path) return -1;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_whitelist_paths.push_back(path);
    return (int)g_whitelist_paths.size();
}

EXPORT int add_suspicious_api(const char* name, const char* category, int risk_score) {
    if (!name || !category) return -1;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_suspicious_apis.push_back({name, category, risk_score});
    return (int)g_suspicious_apis.size();
}

// ============================================================================
// 엔진 정보
// ============================================================================
EXPORT const char* get_engine_stats() {
    std::lock_guard<std::mutex> lock(g_mutex);

    snprintf(g_result_buffer, sizeof(g_result_buffer),
        "{\"version\":\"4.0 Pro\","
        "\"features\":[\"yara\",\"import_analysis\",\"pe_analysis\",\"archive_scan\"],"
        "\"signatures\":%d,\"yara_rules\":%d,\"suspicious_apis\":%d,"
        "\"md5_hashes\":%d,\"sha256_hashes\":%d,"
        "\"whitelist_hashes\":%d,\"whitelist_paths\":%d}",
        (int)g_signatures.size(), (int)g_yara_rules.size(), (int)g_suspicious_apis.size(),
        (int)g_bad_md5.size(), (int)g_bad_sha256.size(),
        (int)g_whitelist_hashes.size(), (int)g_whitelist_paths.size());

    return g_result_buffer;
}

EXPORT const char* get_engine_version() {
    return "4.0 Pro - YARA/Import/PE/Archive";
}
