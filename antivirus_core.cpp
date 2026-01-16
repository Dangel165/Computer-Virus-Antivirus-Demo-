#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <ctime>
#include <algorithm>
#include <thread>
#include <mutex>
#include <future>
#include <openssl/md5.h>
#include <openssl/sha.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#include <windows.h>
#else
#define EXPORT
#include <sys/stat.h>
#endif

// ============================================================================
// 상수 정의
// ============================================================================
const size_t CHUNK_SIZE = 1024 * 1024; // 1MB 청크
const long MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

// ============================================================================
// 스캔 결과 구조체
// ============================================================================
struct ScanResult {
    int status;              // 0=정상, 1=시그니처 탐지, 2=해시 탐지, 3=휴리스틱 탐지, -1=오류
    std::string threat_name; // 탐지된 위협 이름
    std::string hash_md5;    // 파일의 MD5 해시
    std::string hash_sha256; // 파일의 SHA256 해시
    long file_size;          // 파일 크기
    std::string details;     // 추가 정보
};

// ============================================================================
// PE 파일 구조체 (간단한 버전)
// ============================================================================
#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;    // "MZ"
    uint8_t  e_cblp[58];
    uint32_t e_lfanew;   // PE 헤더 오프셋
};

struct PEHeader {
    uint32_t signature;  // "PE\0\0"
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
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
// 시그니처 데이터베이스 (패턴 기반)
// ============================================================================
struct SignaturePattern {
    std::string name;        // 위협 이름
    std::string pattern;     // 검색할 패턴
    int severity;            // 위험도 (1=낮음, 2=중간, 3=높음, 4=치명적)
};

static std::vector<SignaturePattern> signatures = {
    {"Generic.Malware.String", "malware", 3},
    {"Generic.Virus.String", "virus", 3},
    {"Trojan.Generic", "trojan", 4},
    {"Backdoor.Generic", "backdoor", 4},
    {"Ransomware.Generic", "encrypt_files", 4},
    {"Keylogger.Generic", "keylog", 3},
    {"Spyware.Generic", "steal_data", 3},
    {"Rootkit.Generic", "hide_process", 4},
    {"Worm.Generic", "self_replicate", 3},
    {"Adware.Generic", "show_ads", 1},
    // 실제 악성코드 API 호출 패턴
    {"Suspicious.API.CreateRemoteThread", "CreateRemoteThread", 2},
    {"Suspicious.API.WriteProcessMemory", "WriteProcessMemory", 2},
    {"Suspicious.API.VirtualAllocEx", "VirtualAllocEx", 2},
    {"Suspicious.Registry.Persistence", "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 2},
};

static std::mutex sig_mutex; // 시그니처 DB 접근 동기화

// ============================================================================
// 해시 데이터베이스 (알려진 악성 파일)
// ============================================================================
struct HashEntry {
    std::string hash;
    std::string threat_name;
    int severity;
};

static std::vector<HashEntry> bad_hashes = {
    {"098f6bcd4621d373cade4e832627b4f6", "Test.Malware.MD5", 1},
    {"5d41402abc4b2a76b9719d911017c592", "Test.Virus.MD5", 2},
};

static std::vector<HashEntry> bad_sha256_hashes = {
    {"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "Test.Malware.SHA256", 1},
};

static std::mutex hash_mutex; // 해시 DB 접근 동기화

// ============================================================================
// 휴리스틱 분석 규칙
// ============================================================================
struct HeuristicRule {
    std::string name;
    std::vector<std::string> indicators;
    int threshold;
    int severity;
};

static std::vector<HeuristicRule> heuristic_rules = {
    {
        "Heuristic.Ransomware.Behavior",
        {"encrypt", "bitcoin", "payment", "decrypt", ".locked"},
        3,
        4
    },
    {
        "Heuristic.Backdoor.Behavior",
        {"socket", "connect", "recv", "send", "cmd.exe"},
        3,
        4
    },
    {
        "Heuristic.Keylogger.Behavior",
        {"GetAsyncKeyState", "keyboard", "keypress", "log", "capture"},
        3,
        3
    }
};

// ============================================================================
// 로깅 시스템
// ============================================================================
class Logger {
private:
    std::ofstream log_file;
    bool enabled;
    std::mutex log_mutex;

public:
    Logger(const std::string& filename = "antivirus_scan.log") : enabled(true) {
        log_file.open(filename, std::ios::app);
    }

    ~Logger() {
        if (log_file.is_open()) {
            log_file.close();
        }
    }

    void log(const std::string& level, const std::string& message) {
        if (!enabled || !log_file.is_open()) return;

        std::lock_guard<std::mutex> lock(log_mutex);

        time_t now = time(0);
        char timestamp[26];
        ctime_s(timestamp, sizeof(timestamp), &now);
        timestamp[24] = '\0';

        log_file << "[" << timestamp << "] [" << level << "] " << message << std::endl;
        log_file.flush();
    }

    void info(const std::string& msg) { log("INFO", msg); }
    void warning(const std::string& msg) { log("WARNING", msg); }
    void error(const std::string& msg) { log("ERROR", msg); }
    void critical(const std::string& msg) { log("CRITICAL", msg); }
};

static Logger global_logger;

// ============================================================================
// 메모리 최적화: 청크 단위 파일 읽기
// ============================================================================
std::string read_all_chunked(const wchar_t* filepath, long* out_size = nullptr) {
    FILE* file;

    if (_wfopen_s(&file, filepath, L"rb") != 0 || !file) {
        global_logger.error("Failed to open file");
        if (out_size) *out_size = 0;
        return "";
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (out_size) *out_size = size;

    if (size > MAX_FILE_SIZE) {
        global_logger.warning("File too large, reading first 100MB only");
        size = MAX_FILE_SIZE;
    }

    std::string content;
    content.reserve(size);

    // 청크 단위로 읽기
    char buffer[CHUNK_SIZE];
    size_t remaining = size;

    while (remaining > 0) {
        size_t to_read = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        size_t read_bytes = fread(buffer, 1, to_read, file);

        if (read_bytes > 0) {
            content.append(buffer, read_bytes);
            remaining -= read_bytes;
        } else {
            break;
        }
    }

    fclose(file);
    return content;
}

// 기존 read_all 함수 유지 (하위 호환성)
std::string read_all(const wchar_t* filepath, long* out_size = nullptr) {
    return read_all_chunked(filepath, out_size);
}

// ============================================================================
// PE 파일 분석
// ============================================================================
struct PEAnalysisResult {
    bool is_pe;
    bool is_suspicious;
    std::string details;
    int section_count;
    std::vector<std::string> section_names;
    uint32_t timestamp;
};

PEAnalysisResult analyze_pe(const std::string& content) {
    PEAnalysisResult result = {false, false, "", 0, {}, 0};

    if (content.size() < sizeof(DOSHeader)) {
        return result;
    }

    // DOS 헤더 확인
    const DOSHeader* dos = reinterpret_cast<const DOSHeader*>(content.data());
    if (dos->e_magic != 0x5A4D) { // "MZ"
        return result;
    }

    result.is_pe = true;

    // PE 헤더 확인
    if (content.size() < dos->e_lfanew + sizeof(PEHeader)) {
        return result;
    }

    const PEHeader* pe = reinterpret_cast<const PEHeader*>(content.data() + dos->e_lfanew);
    if (pe->signature != 0x00004550) { // "PE\0\0"
        result.is_pe = false;
        return result;
    }

    result.section_count = pe->numberOfSections;
    result.timestamp = pe->timeDateStamp;

    // 섹션 헤더 분석
    size_t section_offset = dos->e_lfanew + sizeof(PEHeader) + pe->sizeOfOptionalHeader;

    for (int i = 0; i < pe->numberOfSections && i < 20; i++) {
        if (content.size() < section_offset + sizeof(SectionHeader)) {
            break;
        }

        const SectionHeader* section = reinterpret_cast<const SectionHeader*>(
            content.data() + section_offset + i * sizeof(SectionHeader)
        );

        std::string section_name(section->name, strnlen(section->name, 8));
        result.section_names.push_back(section_name);

        // 의심스러운 섹션 이름 탐지
        if (section_name.find(".upx") != std::string::npos ||
            section_name.find(".aspack") != std::string::npos ||
            section_name.find(".kkrunchy") != std::string::npos) {
            result.is_suspicious = true;
            result.details += "Packed section detected: " + section_name + "; ";
        }

        // 실행 가능하고 쓰기 가능한 섹션 (의심)
        if ((section->characteristics & 0x20000000) && // 실행 가능
            (section->characteristics & 0x80000000)) { // 쓰기 가능
            result.is_suspicious = true;
            result.details += "Writable+Executable section: " + section_name + "; ";
        }
    }

    return result;
}

// ============================================================================
// MD5 해시 계산
// ============================================================================
std::string calc_md5(const std::string& content) {
    unsigned char md[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)content.data(), content.size(), md);

    std::ostringstream oss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)md[i];
    }
    return oss.str();
}

// ============================================================================
// SHA256 해시 계산
// ============================================================================
std::string calc_sha256(const std::string& content) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)content.data(), content.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

// ============================================================================
// 시그니처 기반 검사
// ============================================================================
bool check_signatures(const std::string& content, SignaturePattern& found_sig) {
    std::lock_guard<std::mutex> lock(sig_mutex);

    std::string content_lower = content;
    std::transform(content_lower.begin(), content_lower.end(),
                   content_lower.begin(), ::tolower);

    for (const auto& sig : signatures) {
        std::string pattern_lower = sig.pattern;
        std::transform(pattern_lower.begin(), pattern_lower.end(),
                       pattern_lower.begin(), ::tolower);

        if (content_lower.find(pattern_lower) != std::string::npos) {
            found_sig = sig;
            global_logger.warning("Signature detected: " + sig.name);
            return true;
        }
    }
    return false;
}

// ============================================================================
// 해시 기반 검사
// ============================================================================
bool check_hash_database(const std::string& md5_hash, const std::string& sha256_hash,
                         HashEntry& found_entry) {
    std::lock_guard<std::mutex> lock(hash_mutex);

    for (const auto& entry : bad_hashes) {
        if (entry.hash == md5_hash) {
            found_entry = entry;
            global_logger.critical("Malicious MD5 hash detected: " + entry.threat_name);
            return true;
        }
    }

    for (const auto& entry : bad_sha256_hashes) {
        if (entry.hash == sha256_hash) {
            found_entry = entry;
            global_logger.critical("Malicious SHA256 hash detected: " + entry.threat_name);
            return true;
        }
    }

    return false;
}

// ============================================================================
// 휴리스틱 분석
// ============================================================================
bool check_heuristics(const std::string& content, HeuristicRule& found_rule) {
    std::string content_lower = content;
    std::transform(content_lower.begin(), content_lower.end(),
                   content_lower.begin(), ::tolower);

    for (const auto& rule : heuristic_rules) {
        int match_count = 0;

        for (const auto& indicator : rule.indicators) {
            std::string indicator_lower = indicator;
            std::transform(indicator_lower.begin(), indicator_lower.end(),
                           indicator_lower.begin(), ::tolower);

            if (content_lower.find(indicator_lower) != std::string::npos) {
                match_count++;
            }
        }

        if (match_count >= rule.threshold) {
            found_rule = rule;
            global_logger.warning("Heuristic detection: " + rule.name +
                                  " (matched " + std::to_string(match_count) +
                                  "/" + std::to_string(rule.indicators.size()) + " indicators)");
            return true;
        }
    }

    return false;
}

// ============================================================================
// 파일 엔트로피 계산
// ============================================================================
double calculate_entropy(const std::string& content) {
    if (content.empty()) return 0.0;

    std::map<unsigned char, int> frequency;
    for (unsigned char c : content) {
        frequency[c]++;
    }

    double entropy = 0.0;
    double size = static_cast<double>(content.size());

    for (const auto& pair : frequency) {
        double probability = pair.second / size;
        entropy -= probability * log2(probability);
    }

    return entropy;
}

// ============================================================================
// 멀티스레드 스캔 (내부 함수)
// ============================================================================
struct ThreadScanResult {
    bool found;
    std::string threat_name;
    int status;
    int severity;
};

ThreadScanResult scan_signatures_thread(const std::string& content) {
    SignaturePattern found_sig;
    if (check_signatures(content, found_sig)) {
        return {true, found_sig.name, 1, found_sig.severity};
    }
    return {false, "", 0, 0};
}

ThreadScanResult scan_heuristics_thread(const std::string& content) {
    HeuristicRule found_rule;
    if (check_heuristics(content, found_rule)) {
        return {true, found_rule.name, 3, found_rule.severity};
    }
    return {false, "", 0, 0};
}

// ============================================================================
// 메인 스캔 함수 (기존 함수 유지)
// ============================================================================
extern "C" {
    // 기본 스캔 함수 (하위 호환성)
    EXPORT int scan_file(const wchar_t* filepath) {
        long file_size;
        std::string content = read_all(filepath, &file_size);

        if (content.empty()) {
            global_logger.error("Failed to read file or file is empty");
            return -1;
        }

        SignaturePattern found_sig;
        if (check_signatures(content, found_sig)) {
            return 1;
        }

        std::string md5_hash = calc_md5(content);
        std::string sha256_hash = calc_sha256(content);
        HashEntry found_hash;
        if (check_hash_database(md5_hash, sha256_hash, found_hash)) {
            return 2;
        }

        HeuristicRule found_rule;
        if (check_heuristics(content, found_rule)) {
            return 3;
        }

        global_logger.info("File is clean");
        return 0;
    }

    // 상세 스캔 함수 (JSON 형식 결과 반환)
    EXPORT const char* scan_file_detailed(const wchar_t* filepath) {
        static std::string result_json;
        result_json.clear();

        long file_size;
        std::string content = read_all(filepath, &file_size);

        if (content.empty()) {
            result_json = "{\"status\":-1,\"error\":\"Failed to read file\"}";
            return result_json.c_str();
        }

        std::string md5_hash = calc_md5(content);
        std::string sha256_hash = calc_sha256(content);
        double entropy = calculate_entropy(content);

        std::ostringstream json;
        json << "{";
        json << "\"file_size\":" << file_size << ",";
        json << "\"md5\":\"" << md5_hash << "\",";
        json << "\"sha256\":\"" << sha256_hash << "\",";
        json << "\"entropy\":" << std::fixed << std::setprecision(4) << entropy << ",";

        SignaturePattern found_sig;
        if (check_signatures(content, found_sig)) {
            json << "\"status\":1,";
            json << "\"threat_type\":\"signature\",";
            json << "\"threat_name\":\"" << found_sig.name << "\",";
            json << "\"severity\":" << found_sig.severity;
            json << "}";
            result_json = json.str();
            return result_json.c_str();
        }

        HashEntry found_hash;
        if (check_hash_database(md5_hash, sha256_hash, found_hash)) {
            json << "\"status\":2,";
            json << "\"threat_type\":\"hash\",";
            json << "\"threat_name\":\"" << found_hash.threat_name << "\",";
            json << "\"severity\":" << found_hash.severity;
            json << "}";
            result_json = json.str();
            return result_json.c_str();
        }

        HeuristicRule found_rule;
        if (check_heuristics(content, found_rule)) {
            json << "\"status\":3,";
            json << "\"threat_type\":\"heuristic\",";
            json << "\"threat_name\":\"" << found_rule.name << "\",";
            json << "\"severity\":" << found_rule.severity;
            json << "}";
            result_json = json.str();
            return result_json.c_str();
        }

        if (entropy > 7.5) {
            json << "\"status\":3,";
            json << "\"threat_type\":\"suspicious\",";
            json << "\"threat_name\":\"High Entropy (Possibly Packed/Encrypted)\",";
            json << "\"severity\":2";
            json << "}";
            result_json = json.str();
            return result_json.c_str();
        }

        json << "\"status\":0,";
        json << "\"threat_type\":\"none\",";
        json << "\"threat_name\":\"Clean\"";
        json << "}";
        result_json = json.str();
        return result_json.c_str();
    }

    // ========================================================================
    // 새로운 기능: 멀티스레드 스캔
    // ========================================================================
    EXPORT const char* scan_file_multithreaded(const wchar_t* filepath) {
        static std::string result_json;
        result_json.clear();

        long file_size;
        std::string content = read_all(filepath, &file_size);

        if (content.empty()) {
            result_json = "{\"status\":-1,\"error\":\"Failed to read file\"}";
            return result_json.c_str();
        }

        // 해시 계산 (메인 스레드)
        std::string md5_hash = calc_md5(content);
        std::string sha256_hash = calc_sha256(content);
        double entropy = calculate_entropy(content);

        // 멀티스레드로 시그니처와 휴리스틱 동시 검사
        auto sig_future = std::async(std::launch::async, scan_signatures_thread, content);
        auto heur_future = std::async(std::launch::async, scan_heuristics_thread, content);

        // 해시 검사 (메인 스레드)
        HashEntry found_hash;
        bool hash_found = check_hash_database(md5_hash, sha256_hash, found_hash);

        // 스레드 결과 대기
        ThreadScanResult sig_result = sig_future.get();
        ThreadScanResult heur_result = heur_future.get();

        std::ostringstream json;
        json << "{";
        json << "\"file_size\":" << file_size << ",";
        json << "\"md5\":\"" << md5_hash << "\",";
        json << "\"sha256\":\"" << sha256_hash << "\",";
        json << "\"entropy\":" << std::fixed << std::setprecision(4) << entropy << ",";
        json << "\"scan_method\":\"multithreaded\",";

        // 우선순위: 시그니처 > 해시 > 휴리스틱
        if (sig_result.found) {
            json << "\"status\":" << sig_result.status << ",";
            json << "\"threat_type\":\"signature\",";
            json << "\"threat_name\":\"" << sig_result.threat_name << "\",";
            json << "\"severity\":" << sig_result.severity;
        } else if (hash_found) {
            json << "\"status\":2,";
            json << "\"threat_type\":\"hash\",";
            json << "\"threat_name\":\"" << found_hash.threat_name << "\",";
            json << "\"severity\":" << found_hash.severity;
        } else if (heur_result.found) {
            json << "\"status\":" << heur_result.status << ",";
            json << "\"threat_type\":\"heuristic\",";
            json << "\"threat_name\":\"" << heur_result.threat_name << "\",";
            json << "\"severity\":" << heur_result.severity;
        } else if (entropy > 7.5) {
            json << "\"status\":3,";
            json << "\"threat_type\":\"suspicious\",";
            json << "\"threat_name\":\"High Entropy (Possibly Packed/Encrypted)\",";
            json << "\"severity\":2";
        } else {
            json << "\"status\":0,";
            json << "\"threat_type\":\"none\",";
            json << "\"threat_name\":\"Clean\"";
        }

        json << "}";
        result_json = json.str();
        return result_json.c_str();
    }

    // ========================================================================
    // 새로운 기능: PE 파일 분석
    // ========================================================================
    EXPORT const char* analyze_pe_file(const wchar_t* filepath) {
        static std::string result_json;
        result_json.clear();

        long file_size;
        std::string content = read_all(filepath, &file_size);

        if (content.empty()) {
            result_json = "{\"error\":\"Failed to read file\"}";
            return result_json.c_str();
        }

        PEAnalysisResult pe_result = analyze_pe(content);

        std::ostringstream json;
        json << "{";
        json << "\"is_pe\":" << (pe_result.is_pe ? "true" : "false") << ",";
        json << "\"is_suspicious\":" << (pe_result.is_suspicious ? "true" : "false") << ",";
        json << "\"section_count\":" << pe_result.section_count << ",";
        json << "\"timestamp\":" << pe_result.timestamp << ",";
        json << "\"details\":\"" << pe_result.details << "\",";
        json << "\"sections\":[";

        for (size_t i = 0; i < pe_result.section_names.size(); i++) {
            json << "\"" << pe_result.section_names[i] << "\"";
            if (i < pe_result.section_names.size() - 1) {
                json << ",";
            }
        }

        json << "]}";
        result_json = json.str();
        return result_json.c_str();
    }

    // ========================================================================
    // 새로운 기능: 통합 고급 스캔 (모든 기능 포함)
    // ========================================================================
    EXPORT const char* scan_file_advanced(const wchar_t* filepath) {
        static std::string result_json;
        result_json.clear();

        long file_size;
        std::string content = read_all(filepath, &file_size);

        if (content.empty()) {
            result_json = "{\"status\":-1,\"error\":\"Failed to read file\"}";
            return result_json.c_str();
        }

        // 해시 계산
        std::string md5_hash = calc_md5(content);
        std::string sha256_hash = calc_sha256(content);
        double entropy = calculate_entropy(content);

        // PE 분석
        PEAnalysisResult pe_result = analyze_pe(content);

        // 멀티스레드 스캔
        auto sig_future = std::async(std::launch::async, scan_signatures_thread, content);
        auto heur_future = std::async(std::launch::async, scan_heuristics_thread, content);

        HashEntry found_hash;
        bool hash_found = check_hash_database(md5_hash, sha256_hash, found_hash);

        ThreadScanResult sig_result = sig_future.get();
        ThreadScanResult heur_result = heur_future.get();

        std::ostringstream json;
        json << "{";
        json << "\"file_size\":" << file_size << ",";
        json << "\"md5\":\"" << md5_hash << "\",";
        json << "\"sha256\":\"" << sha256_hash << "\",";
        json << "\"entropy\":" << std::fixed << std::setprecision(4) << entropy << ",";
        json << "\"scan_method\":\"advanced\",";

        // PE 정보 추가
        json << "\"pe_info\":{";
        json << "\"is_pe\":" << (pe_result.is_pe ? "true" : "false") << ",";
        json << "\"is_suspicious\":" << (pe_result.is_suspicious ? "true" : "false") << ",";
        json << "\"section_count\":" << pe_result.section_count << ",";
        json << "\"details\":\"" << pe_result.details << "\"";
        json << "},";

        // 탐지 결과
        if (sig_result.found) {
            json << "\"status\":" << sig_result.status << ",";
            json << "\"threat_type\":\"signature\",";
            json << "\"threat_name\":\"" << sig_result.threat_name << "\",";
            json << "\"severity\":" << sig_result.severity;
        } else if (hash_found) {
            json << "\"status\":2,";
            json << "\"threat_type\":\"hash\",";
            json << "\"threat_name\":\"" << found_hash.threat_name << "\",";
            json << "\"severity\":" << found_hash.severity;
        } else if (pe_result.is_suspicious) {
            json << "\"status\":3,";
            json << "\"threat_type\":\"pe_suspicious\",";
            json << "\"threat_name\":\"Suspicious PE Structure\",";
            json << "\"severity\":3";
        } else if (heur_result.found) {
            json << "\"status\":" << heur_result.status << ",";
            json << "\"threat_type\":\"heuristic\",";
            json << "\"threat_name\":\"" << heur_result.threat_name << "\",";
            json << "\"severity\":" << heur_result.severity;
        } else if (entropy > 7.5) {
            json << "\"status\":3,";
            json << "\"threat_type\":\"suspicious\",";
            json << "\"threat_name\":\"High Entropy (Possibly Packed/Encrypted)\",";
            json << "\"severity\":2";
        } else {
            json << "\"status\":0,";
            json << "\"threat_type\":\"none\",";
            json << "\"threat_name\":\"Clean\"";
        }

        json << "}";
        result_json = json.str();
        return result_json.c_str();
    }

    // ========================================================================
    // 기존 함수 유지
    // ========================================================================
    EXPORT int add_signature(const char* name, const char* pattern, int severity) {
        std::lock_guard<std::mutex> lock(sig_mutex);
        signatures.push_back({name, pattern, severity});
        global_logger.info("Added signature: " + std::string(name));
        return signatures.size();
    }

    EXPORT int add_hash(const char* hash, const char* threat_name, int severity, bool is_sha256) {
        std::lock_guard<std::mutex> lock(hash_mutex);
        if (is_sha256) {
            bad_sha256_hashes.push_back({hash, threat_name, severity});
        } else {
            bad_hashes.push_back({hash, threat_name, severity});
        }
        global_logger.info("Added hash: " + std::string(threat_name));
        return is_sha256 ? bad_sha256_hashes.size() : bad_hashes.size();
    }

    // ========================================================================
    // 새로운 기능: 통계 정보
    // ========================================================================
    EXPORT const char* get_engine_stats() {
        static std::string stats_json;

        std::lock_guard<std::mutex> sig_lock(sig_mutex);
        std::lock_guard<std::mutex> hash_lock(hash_mutex);

        std::ostringstream json;
        json << "{";
        json << "\"signature_count\":" << signatures.size() << ",";
        json << "\"md5_hash_count\":" << bad_hashes.size() << ",";
        json << "\"sha256_hash_count\":" << bad_sha256_hashes.size() << ",";
        json << "\"heuristic_rules\":" << heuristic_rules.size() << ",";
        json << "\"version\":\"3.0 Advanced\",";
        json << "\"features\":[\"multithreading\",\"pe_analysis\",\"memory_optimized\",\"chunk_reading\"]";
        json << "}";

        stats_json = json.str();
        return stats_json.c_str();
    }
}
