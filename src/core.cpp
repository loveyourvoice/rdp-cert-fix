// Диагностика и ремонт TLS-сертификата RDP, который ломает КриптоПро CSP.
//
// Симптом: RDP рвёт любое подключение сразу после X.224, в журнале System
//   TerminalServices-RemoteConnectionManager 1057 «Указан неправильный алгоритм»
//   Schannel 36870, код 0x8009030D.
// Лечение: убрать сломанные сертификаты, выпустить свой самоподписанный RSA-2048/SHA-256
// через Microsoft Software Key Storage Provider, дать NETWORK SERVICE чтение ключа,
// привязать отпечаток к RDP-Tcp и перезапустить службу.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <sddl.h>
#include <aclapi.h>
#include <objbase.h>
#include <winevt.h>
#include <cstdio>
#include <cstdarg>

#include "core.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wevtapi.lib")

namespace {

const wchar_t* kFriendlyName = L"RDP (rdp-cert-fix)";
// Имена, которыми помечались сертификаты, выпущенные раньше вручную - их тоже чистим.
const wchar_t* kOwnFriendlyNames[] = { L"RDP (rdp-cert-fix)", L"RDP (manual)" };
const wchar_t* kTsKey = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
const wchar_t* kTsPolicyKey = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services";
const wchar_t* kRdpTcpKey = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";

// ---------- строки ----------

std::string W2U(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::string Fmt(const char* fmt, ...) {
    char buf[1024];
    va_list a; va_start(a, fmt);
    vsnprintf(buf, sizeof(buf), fmt, a);
    va_end(a);
    return buf;
}

std::string ErrText(DWORD code) {
    wchar_t* buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring s = buf ? buf : L"";
    if (buf) LocalFree(buf);
    while (!s.empty() && (s.back() == L'\n' || s.back() == L'\r' || s.back() == L' ' || s.back() == L'.')) s.pop_back();
    std::string hex = Fmt("0x%08X", code);
    return s.empty() ? hex : W2U(s) + " (" + hex + ")";
}

std::string Hex(const BYTE* p, DWORD n) {
    std::string s;
    for (DWORD i = 0; i < n; ++i) s += Fmt("%02X", p[i]);
    return s;
}

std::string DateStr(const FILETIME& ft) {
    FILETIME local; SYSTEMTIME st;
    FileTimeToLocalFileTime(&ft, &local);
    FileTimeToSystemTime(&local, &st);
    return Fmt("%02u.%02u.%04u", st.wDay, st.wMonth, st.wYear);
}

std::string TimeStr(const FILETIME& ft) {
    FILETIME local; SYSTEMTIME st;
    FileTimeToLocalFileTime(&ft, &local);
    FileTimeToSystemTime(&local, &st);
    return Fmt("%02u:%02u", st.wHour, st.wMinute);
}

// ---------- реестр ----------

bool RegDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD& out) {
    DWORD cb = sizeof(out), type = 0;
    return RegGetValueW(root, path, name, RRF_RT_REG_DWORD, &type, &out, &cb) == ERROR_SUCCESS;
}

bool RegBinary(HKEY root, const wchar_t* path, const wchar_t* name, std::vector<BYTE>& out) {
    DWORD cb = 0;
    if (RegGetValueW(root, path, name, RRF_RT_REG_BINARY, nullptr, nullptr, &cb) != ERROR_SUCCESS) return false;
    out.resize(cb);
    return RegGetValueW(root, path, name, RRF_RT_REG_BINARY, nullptr, out.data(), &cb) == ERROR_SUCCESS;
}

bool RegKeyExists(HKEY root, const wchar_t* path, REGSAM view) {
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | view, &k) != ERROR_SUCCESS) return false;
    RegCloseKey(k);
    return true;
}

DWORD RdpPort() {
    DWORD port = 3389;
    RegDword(HKEY_LOCAL_MACHINE, kRdpTcpKey, L"PortNumber", port);
    return port;
}

// ---------- службы ----------

struct SvcInfo {
    bool found = false;
    DWORD state = 0;
    FILETIME started{};
    bool hasStart = false;
};

SvcInfo QuerySvc(const wchar_t* name) {
    SvcInfo r;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return r;
    SC_HANDLE s = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    if (s) {
        SERVICE_STATUS_PROCESS sp{}; DWORD cb = 0;
        if (QueryServiceStatusEx(s, SC_STATUS_PROCESS_INFO, (LPBYTE)&sp, sizeof(sp), &cb)) {
            r.found = true;
            r.state = sp.dwCurrentState;
            if (sp.dwProcessId) {
                HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sp.dwProcessId);
                if (p) {
                    FILETIME c, e, k, u;
                    if (GetProcessTimes(p, &c, &e, &k, &u)) { r.started = c; r.hasStart = true; }
                    CloseHandle(p);
                }
            }
        }
        CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
    return r;
}

bool WaitSvc(SC_HANDLE s, DWORD want, DWORD timeoutMs) {
    SERVICE_STATUS st{};
    for (DWORD t = 0; t < timeoutMs; t += 250) {
        if (!QueryServiceStatus(s, &st)) return false;
        if (st.dwCurrentState == want) return true;
        Sleep(250);
    }
    return false;
}

// ---------- журнал событий ----------

// Число событий провайдера/кода в журнале System начиная с момента since.
int CountEvents(const wchar_t* provider, int id, const FILETIME& since) {
    SYSTEMTIME st; FileTimeToSystemTime(&since, &st);
    wchar_t q[512];
    swprintf_s(q, L"*[System[Provider[@Name='%ls'] and EventID=%d and TimeCreated[@SystemTime>='%04u-%02u-%02uT%02u:%02u:%02u.000Z']]]",
               provider, id, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    EVT_HANDLE h = EvtQuery(nullptr, L"System", q, EvtQueryChannelPath | EvtQueryForwardDirection);
    if (!h) return -1;
    int count = 0;
    EVT_HANDLE ev[64]; DWORD got = 0;
    while (EvtNext(h, 64, ev, 1000, 0, &got)) {
        count += (int)got;
        for (DWORD i = 0; i < got; ++i) EvtClose(ev[i]);
    }
    EvtClose(h);
    return count;
}

// ---------- ключи и права ----------

PSID NetworkServiceSid() {
    static BYTE sid[SECURITY_MAX_SID_SIZE];
    static bool init = false;
    if (!init) {
        DWORD cb = sizeof(sid);
        CreateWellKnownSid(WinNetworkServiceSid, nullptr, sid, &cb);
        init = true;
    }
    return sid;
}

// Есть ли в DACL разрешение на чтение для NETWORK SERVICE (под ней работает TermService).
bool DaclAllowsNetworkService(PSECURITY_DESCRIPTOR sd) {
    BOOL present = FALSE, defaulted = FALSE; PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) return false;
    if (!present || !dacl) return true;  // NULL DACL - доступ всем
    const DWORD readMask = FILE_READ_DATA | GENERIC_READ | GENERIC_ALL;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        ACE_HEADER* h = nullptr;
        if (!GetAce(dacl, i, (LPVOID*)&h) || h->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        auto* a = reinterpret_cast<ACCESS_ALLOWED_ACE*>(h);
        PSID sid = &a->SidStart;
        if ((a->Mask & readMask) == 0) continue;
        if (EqualSid(sid, NetworkServiceSid())) return true;
        // Everyone / Authenticated Users / BUILTIN\Users тоже подходят
        BYTE wk[SECURITY_MAX_SID_SIZE]; DWORD cb;
        for (WELL_KNOWN_SID_TYPE t : { WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid }) {
            cb = sizeof(wk);
            if (CreateWellKnownSid(t, nullptr, wk, &cb) && EqualSid(sid, wk)) return true;
        }
    }
    return false;
}

enum class KeyState { Ok, Missing, NoAccess, Unknown };

KeyState CheckCertKey(PCCERT_CONTEXT c, std::string& err) {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL mustFree = FALSE;
    if (!CryptAcquireCertificatePrivateKey(c, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                                           nullptr, &h, &spec, &mustFree)) {
        err = ErrText(GetLastError());
        return KeyState::Missing;
    }
    KeyState result = KeyState::Unknown;
    if (spec == CERT_NCRYPT_KEY_SPEC) {
        DWORD cb = 0;
        if (NCryptGetProperty(h, NCRYPT_SECURITY_DESCR_PROPERTY, nullptr, 0, &cb, DACL_SECURITY_INFORMATION) == ERROR_SUCCESS) {
            std::vector<BYTE> sd(cb);
            if (NCryptGetProperty(h, NCRYPT_SECURITY_DESCR_PROPERTY, sd.data(), cb, &cb, DACL_SECURITY_INFORMATION) == ERROR_SUCCESS)
                result = DaclAllowsNetworkService(sd.data()) ? KeyState::Ok : KeyState::NoAccess;
        }
        if (mustFree) NCryptFreeObject(h);
    } else {
        DWORD cb = 0;
        if (CryptGetProvParam(h, PP_KEYSET_SEC_DESCR, nullptr, &cb, DACL_SECURITY_INFORMATION)) {
            std::vector<BYTE> sd(cb);
            if (CryptGetProvParam(h, PP_KEYSET_SEC_DESCR, sd.data(), &cb, DACL_SECURITY_INFORMATION))
                result = DaclAllowsNetworkService(sd.data()) ? KeyState::Ok : KeyState::NoAccess;
        }
        if (mustFree) CryptReleaseContext(h, 0);
    }
    return result;
}

PCCERT_CONTEXT FindCert(const wchar_t* store, const std::vector<BYTE>& hash) {
    HCERTSTORE s = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                 CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, store);
    if (!s) return nullptr;
    CRYPT_HASH_BLOB b{ (DWORD)hash.size(), const_cast<BYTE*>(hash.data()) };
    PCCERT_CONTEXT c = CertFindCertificateInStore(s, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &b, nullptr);
    CertCloseStore(s, 0);
    return c;
}

PCCERT_CONTEXT FirstCert(const wchar_t* store) {
    HCERTSTORE s = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                 CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, store);
    if (!s) return nullptr;
    PCCERT_CONTEXT c = CertEnumCertificatesInStore(s, nullptr);
    PCCERT_CONTEXT dup = c ? CertDuplicateCertificateContext(c) : nullptr;
    if (c) CertFreeCertificateContext(c);
    CertCloseStore(s, 0);
    return dup;
}

std::string CertName(PCCERT_CONTEXT c) {
    wchar_t n[256] = {};
    CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, n, 256);
    return W2U(n);
}

std::string Thumb(PCCERT_CONTEXT c) {
    BYTE h[20]; DWORD cb = sizeof(h);
    if (!CertGetCertificateContextProperty(c, CERT_SHA1_HASH_PROP_ID, h, &cb)) return "?";
    return Hex(h, cb);
}

std::wstring FriendlyName(PCCERT_CONTEXT c) {
    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(c, CERT_FRIENDLY_NAME_PROP_ID, nullptr, &cb) || cb < sizeof(wchar_t))
        return L"";
    std::wstring s(cb / sizeof(wchar_t), L'\0');
    CertGetCertificateContextProperty(c, CERT_FRIENDLY_NAME_PROP_ID, &s[0], &cb);
    while (!s.empty() && s.back() == L'\0') s.pop_back();
    return s;
}

// ---------- рукопожатие RDP ----------

// X.224 Connection Request на localhost. true, если сервер прислал Connection Confirm.
bool RdpHandshake(DWORD port, std::string& detail) {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) { detail = "Winsock не запустился"; return false; }
    bool ok = false;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    DWORD tmo = 4000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons((u_short)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof(a)) != 0) {
        detail = Fmt("порт %lu закрыт", port);
    } else {
        static const unsigned char cr[] = { 0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,
                                            0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00 };
        send(s, (const char*)cr, sizeof(cr), 0);
        unsigned char r[64]; int n = recv(s, (char*)r, sizeof(r), 0);
        if (n >= 6 && r[0] == 0x03 && r[5] == 0xD0) {
            ok = true;
            const char* proto = "RDP";
            if (n >= 19 && r[11] == 0x02) {
                switch (r[15]) {
                case 1: proto = "TLS"; break;
                case 2: proto = "TLS + NLA"; break;
                case 8: proto = "TLS + NLA (EX)"; break;
                }
            }
            detail = Fmt("отвечает, протокол %s", proto);
        } else {
            detail = n > 0 ? "неожиданный ответ" : "сервер закрыл соединение без ответа";
        }
    }
    closesocket(s);
    WSACleanup();
    return ok;
}

bool CryptoProInstalled() {
    return RegKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Crypto Pro", KEY_WOW64_64KEY) ||
           RegKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Crypto Pro", KEY_WOW64_32KEY);
}

// ---------- ремонт ----------

struct Fatal { std::string msg; };

void Check(bool cond, const std::string& what, DWORD code) {
    if (!cond) throw Fatal{ what + ": " + ErrText(code) };
}
void CheckNt(SECURITY_STATUS st, const std::string& what) {
    if (st != ERROR_SUCCESS) throw Fatal{ what + ": " + ErrText((DWORD)st) };
}

struct Logger {
    const LogFn& fn;
    int warnings = 0;
    void step(const std::string& t) { fn({ Level::Info, t, true }); }
    void ok(const std::string& t) { fn({ Level::Ok, t, false }); }
    void info(const std::string& t) { fn({ Level::Info, t, false }); }
    void warn(const std::string& t) { fn({ Level::Warn, t, false }); ++warnings; }
    void bad(const std::string& t) { fn({ Level::Bad, t, false }); }
};

void StopSvc(Logger& L, SC_HANDLE scm, const wchar_t* name) {
    std::string n = W2U(name);
    SC_HANDLE s = OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!s) { L.warn(n + " не открылась: " + ErrText(GetLastError())); return; }
    SERVICE_STATUS st{};
    QueryServiceStatus(s, &st);
    if (st.dwCurrentState == SERVICE_STOPPED) {
        L.ok(n + " уже остановлена");
    } else if (!ControlService(s, SERVICE_CONTROL_STOP, &st) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
        L.warn(n + " не останавливается: " + ErrText(GetLastError()));
    } else if (!WaitSvc(s, SERVICE_STOPPED, 30000)) {
        L.warn(n + " не остановилась за 30 с");
    } else {
        L.ok(n + " остановлена");
    }
    CloseServiceHandle(s);
}

void StartSvc(Logger& L, SC_HANDLE scm, const wchar_t* name) {
    std::string n = W2U(name);
    SC_HANDLE s = OpenServiceW(scm, name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!s) { L.warn(n + " не открылась: " + ErrText(GetLastError())); return; }
    if (!StartServiceW(s, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        L.warn(n + " не запускается: " + ErrText(GetLastError()));
    else if (!WaitSvc(s, SERVICE_RUNNING, 30000))
        L.warn(n + " не запустилась за 30 с");
    else
        L.ok(n + " запущена");
    CloseServiceHandle(s);
}

// Удаляет закрытый ключ, на который ссылается сертификат (CNG или старый CAPI).
void DeletePrivateKey(Logger& L, PCCERT_CONTEXT c) {
    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &cb)) return;
    std::vector<BYTE> buf(cb);
    auto* kpi = reinterpret_cast<CRYPT_KEY_PROV_INFO*>(buf.data());
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, kpi, &cb)) return;

    std::string name = W2U(kpi->pwszContainerName ? kpi->pwszContainerName : L"?");
    bool machine = (kpi->dwFlags & CRYPT_MACHINE_KEYSET) != 0;
    if (kpi->dwProvType == 0) {
        NCRYPT_PROV_HANDLE prov = 0; NCRYPT_KEY_HANDLE key = 0;
        SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, kpi->pwszProvName, 0);
        if (st == ERROR_SUCCESS)
            st = NCryptOpenKey(prov, &key, kpi->pwszContainerName, 0, machine ? NCRYPT_MACHINE_KEY_FLAG : 0);
        if (st == ERROR_SUCCESS)
            st = NCryptDeleteKey(key, 0);  // освобождает key
        if (prov) NCryptFreeObject(prov);
        if (st == ERROR_SUCCESS) L.ok("ключ " + name + " удалён");
        else L.warn("ключ " + name + " не удалён: " + ErrText((DWORD)st));
    } else {
        HCRYPTPROV h = 0;
        if (CryptAcquireContextW(&h, kpi->pwszContainerName, kpi->pwszProvName, kpi->dwProvType,
                                 CRYPT_DELETEKEYSET | (machine ? CRYPT_MACHINE_KEYSET : 0)))
            L.ok("ключ " + name + " удалён");
        else
            L.warn("ключ " + name + " не удалён: " + ErrText(GetLastError()));
    }
}

// Удаляет из LocalMachine\<store> сертификаты под фильтр вместе с ключами.
template <class Pred>
int PurgeStore(Logger& L, const wchar_t* storeName, Pred match) {
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, storeName);
    if (!store) return 0;
    std::vector<PCCERT_CONTEXT> victims;
    PCCERT_CONTEXT c = nullptr;
    while ((c = CertEnumCertificatesInStore(store, c)) != nullptr)
        if (match(c)) victims.push_back(CertDuplicateCertificateContext(c));
    for (PCCERT_CONTEXT v : victims) {
        std::string tp = Thumb(v);
        DeletePrivateKey(L, v);
        if (CertDeleteCertificateFromStore(v))  // освобождает v
            L.ok("сертификат " + tp + " удалён из " + W2U(storeName));
        else
            L.warn("сертификат " + tp + " не удалён: " + ErrText(GetLastError()));
    }
    CertCloseStore(store, 0);
    return (int)victims.size();
}

struct Encoded {
    BYTE* data = nullptr; DWORD size = 0;
    ~Encoded() { if (data) LocalFree(data); }
};
void Encode(LPCSTR type, const void* obj, Encoded& out, const char* what) {
    Check(CryptEncodeObjectEx(X509_ASN_ENCODING, type, obj, CRYPT_ENCODE_ALLOC_FLAG, nullptr, &out.data, &out.size) != FALSE,
          std::string("кодирование ") + what, GetLastError());
}

std::wstring NewKeyName() {
    GUID g{}; CoCreateGuid(&g);
    wchar_t s[64]; StringFromGUID2(g, s, 64);
    return std::wstring(L"rdp-cert-fix-") + s;
}

// Выпускает сертификат в LocalMachine\My и возвращает его SHA1-отпечаток.
std::vector<BYTE> IssueCertificate(Logger& L, const std::wstring& host) {
    NCRYPT_PROV_HANDLE prov = 0; NCRYPT_KEY_HANDLE key = 0;
    CheckNt(NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0), "открытие Microsoft Software KSP");
    std::wstring keyName = NewKeyName();
    CheckNt(NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM, keyName.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG),
            "создание ключа");
    DWORD len = 2048, exportPolicy = 0, usage = NCRYPT_ALLOW_ALL_USAGES;
    CheckNt(NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&len, sizeof(len), 0), "длина ключа");
    CheckNt(NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&exportPolicy, sizeof(exportPolicy), 0), "политика экспорта");
    CheckNt(NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&usage, sizeof(usage), 0), "назначение ключа");
    CheckNt(NCryptFinalizeKey(key, 0), "генерация ключа");
    L.ok("ключ RSA-2048 создан в Microsoft Software KSP");

    // SYSTEM и администраторы - полный доступ, NETWORK SERVICE (под ней TermService) - чтение.
    PSECURITY_DESCRIPTOR sd = nullptr; ULONG sdLen = 0;
    Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;NS)",
                                                               SDDL_REVISION_1, &sd, &sdLen) != FALSE,
          "SDDL", GetLastError());
    SECURITY_STATUS st = NCryptSetProperty(key, NCRYPT_SECURITY_DESCR_PROPERTY, (PBYTE)sd, sdLen, DACL_SECURITY_INFORMATION);
    LocalFree(sd);
    CheckNt(st, "права на ключ для NETWORK SERVICE");
    L.ok("служба RDP (NETWORK SERVICE) получила доступ к ключу");

    std::wstring subject = L"CN=" + host;
    DWORD nameLen = 0;
    Check(CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR, nullptr, nullptr, &nameLen, nullptr) != FALSE,
          "имя субъекта", GetLastError());
    std::vector<BYTE> nameBuf(nameLen);
    Check(CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR, nullptr, nameBuf.data(), &nameLen, nullptr) != FALSE,
          "имя субъекта", GetLastError());
    CERT_NAME_BLOB subj{ nameLen, nameBuf.data() };

    LPSTR ekuOid = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
    CERT_ENHKEY_USAGE eku{ 1, &ekuOid };
    Encoded ekuEnc; Encode(X509_ENHANCED_KEY_USAGE, &eku, ekuEnc, "EKU");

    BYTE kuBits = CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE;
    CRYPT_BIT_BLOB ku{ 1, &kuBits, 0 };
    Encoded kuEnc; Encode(X509_KEY_USAGE, &ku, kuEnc, "KeyUsage");

    CERT_ALT_NAME_ENTRY san{}; san.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; san.pwszDNSName = (LPWSTR)host.c_str();
    CERT_ALT_NAME_INFO sanInfo{ 1, &san };
    Encoded sanEnc; Encode(X509_ALTERNATE_NAME, &sanInfo, sanEnc, "SAN");

    CERT_EXTENSION ext[3] = {
        { (LPSTR)szOID_ENHANCED_KEY_USAGE, FALSE, { ekuEnc.size, ekuEnc.data } },
        { (LPSTR)szOID_KEY_USAGE, TRUE, { kuEnc.size, kuEnc.data } },
        { (LPSTR)szOID_SUBJECT_ALT_NAME2, FALSE, { sanEnc.size, sanEnc.data } },
    };
    CERT_EXTENSIONS exts{ 3, ext };

    CRYPT_KEY_PROV_INFO kpi{};
    kpi.pwszContainerName = (LPWSTR)keyName.c_str();
    kpi.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
    kpi.dwProvType = 0;  // 0 = CNG
    kpi.dwFlags = NCRYPT_MACHINE_KEY_FLAG;

    CRYPT_ALGORITHM_IDENTIFIER alg{ (LPSTR)szOID_RSA_SHA256RSA, {} };

    FILETIME now; GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER u{ now.dwLowDateTime, now.dwHighDateTime };
    const ULONGLONG day = 864000000000ULL;  // 100-нс интервалов в сутках
    ULARGE_INTEGER b = u, e = u;
    b.QuadPart -= day;
    e.QuadPart += day * 3652;  // ~10 лет
    FILETIME fb{ b.LowPart, b.HighPart }, fe{ e.LowPart, e.HighPart };
    SYSTEMTIME start, end;
    FileTimeToSystemTime(&fb, &start); FileTimeToSystemTime(&fe, &end);

    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(key, &subj, 0, &kpi, &alg, &start, &end, &exts);
    Check(cert != nullptr, "выпуск сертификата", GetLastError());

    HCERTSTORE my = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
    Check(my != nullptr, "открытие LocalMachine\\My", GetLastError());
    PCCERT_CONTEXT added = nullptr;
    Check(CertAddCertificateContextToStore(my, cert, CERT_STORE_ADD_NEW, &added) != FALSE,
          "сохранение в LocalMachine\\My", GetLastError());
    CRYPT_DATA_BLOB fn{ (DWORD)((wcslen(kFriendlyName) + 1) * sizeof(wchar_t)), (BYTE*)kFriendlyName };
    CertSetCertificateContextProperty(added, CERT_FRIENDLY_NAME_PROP_ID, 0, &fn);

    std::string keyErr;
    if (CheckCertKey(added, keyErr) == KeyState::Missing)
        L.warn("ключ нового сертификата не открывается: " + keyErr);

    std::vector<BYTE> hash(20); DWORD cb = 20;
    CertGetCertificateContextProperty(added, CERT_SHA1_HASH_PROP_ID, hash.data(), &cb);
    L.ok("сертификат CN=" + W2U(host) + " выпущен до " + DateStr(fe));
    L.info("отпечаток " + Hex(hash.data(), 20));

    CertFreeCertificateContext(added);
    CertFreeCertificateContext(cert);
    CertCloseStore(my, 0);
    NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return hash;
}

}  // namespace

bool IsProcessElevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{}; DWORD len = 0;
    BOOL ok = GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &len);
    CloseHandle(tok);
    return ok && el.TokenIsElevated;
}

Status RunChecks() {
    Status st;
    auto add = [&](std::string t, std::string v, Level l, std::string hint = {}) {
        st.items.push_back({ std::move(t), std::move(v), std::move(hint), l });
    };

    // 1. Разрешены ли подключения (политика важнее локальной настройки).
    DWORD deny = 0, denyPolicy = 0;
    bool hasPolicy = RegDword(HKEY_LOCAL_MACHINE, kTsPolicyKey, L"fDenyTSConnections", denyPolicy);
    RegDword(HKEY_LOCAL_MACHINE, kTsKey, L"fDenyTSConnections", deny);
    bool rdpOff = hasPolicy ? denyPolicy != 0 : deny != 0;
    add("Удалённый рабочий стол", rdpOff ? (hasPolicy ? "запрещён групповой политикой" : "выключен") : "включён",
        rdpOff ? Level::Bad : Level::Ok,
        rdpOff ? "Включите в «Параметры → Система → Удалённый рабочий стол». Эта утилита настройку не меняет." : "");

    // 2. Служба.
    SvcInfo svc = QuerySvc(L"TermService");
    bool svcRunning = svc.found && svc.state == SERVICE_RUNNING;
    add("Служба TermService",
        !svc.found ? "не найдена" : svcRunning ? (svc.hasStart ? "работает с " + TimeStr(svc.started) : "работает") : "остановлена",
        svcRunning ? Level::Ok : Level::Warn);

    // 3. Порт и NLA.
    DWORD port = RdpPort();
    DWORD nla = 0;
    RegDword(HKEY_LOCAL_MACHINE, kRdpTcpKey, L"UserAuthentication", nla);
    add("Порт RDP", std::to_string(port), Level::Info);
    add("Проверка подлинности (NLA)", nla ? "включена" : "выключена", nla ? Level::Ok : Level::Info,
        nla ? "" : "Без NLA экран входа Windows виден до ввода пароля. Рекомендуется включить.");

    // 4. КриптоПро.
    bool cp = CryptoProInstalled();
    add("КриптоПро CSP", cp ? "установлен" : "не найден", Level::Info,
        cp ? "КриптоПро мешает Windows создать сертификат RDP - типичная причина поломки." : "");

    // 5. Сертификат.
    bool certBad = false;
    std::vector<BYTE> bound;
    bool hasBound = RegBinary(HKEY_LOCAL_MACHINE, kRdpTcpKey, L"SSLCertificateSHA1Hash", bound) && bound.size() == 20;
    PCCERT_CONTEXT cert = nullptr;
    std::string origin;
    if (hasBound) {
        cert = FindCert(L"MY", bound);
        if (!cert) cert = FindCert(L"Remote Desktop", bound);
        origin = "привязан вручную";
    } else {
        cert = FirstCert(L"Remote Desktop");
        origin = "создан Windows";
    }
    if (!cert) {
        certBad = true;
        add("Сертификат RDP",
            hasBound ? "привязан, но не найден в хранилище" : "отсутствует",
            Level::Bad,
            hasBound ? "Отпечаток " + Hex(bound.data(), 20) + " записан в RDP-Tcp, но сертификата с ним нет."
                     : "Windows не смогла создать самоподписанный сертификат RDP.");
    } else {
        FILETIME now; GetSystemTimeAsFileTime(&now);
        bool expired = CompareFileTime(&cert->pCertInfo->NotAfter, &now) < 0;
        std::string tp = Thumb(cert);
        std::string value = CertName(cert) + ", до " + DateStr(cert->pCertInfo->NotAfter);
        std::string hint = "Отпечаток " + tp + " (" + origin + ")";
        if (expired) {
            certBad = true;
            add("Сертификат RDP", value + " - истёк", Level::Bad, hint);
        } else {
            add("Сертификат RDP", value, Level::Ok, hint);
        }
        std::string err;
        switch (CheckCertKey(cert, err)) {
        case KeyState::Ok: add("Закрытый ключ сертификата", "доступен службе", Level::Ok); break;
        case KeyState::Unknown: add("Закрытый ключ сертификата", "есть", Level::Ok); break;
        case KeyState::NoAccess:
            certBad = true;
            add("Закрытый ключ сертификата", "у службы нет доступа", Level::Bad,
                "У NETWORK SERVICE нет права чтения ключа - TermService не сможет установить TLS.");
            break;
        case KeyState::Missing:
            certBad = true;
            add("Закрытый ключ сертификата", "не открывается", Level::Bad, err);
            break;
        }
        CertFreeCertificateContext(cert);
    }

    // 6. Ошибки в журнале с момента запуска службы (или за сутки).
    FILETIME since;
    if (svc.hasStart) {
        since = svc.started;
    } else {
        GetSystemTimeAsFileTime(&since);
        ULARGE_INTEGER u{ since.dwLowDateTime, since.dwHighDateTime };
        u.QuadPart -= 864000000000ULL;
        since = { u.LowPart, u.HighPart };
    }
    int schannel = CountEvents(L"Schannel", 36870, since);
    int ts1057 = CountEvents(L"Microsoft-Windows-TerminalServices-RemoteConnectionManager", 1057, since);
    std::string period = svc.hasStart ? "с запуска службы" : "за сутки";
    if (schannel < 0) {
        add("Ошибки TLS в журнале", "журнал недоступен", Level::Info);
    } else {
        add("Ошибки TLS в журнале", schannel ? Fmt("%d %s", schannel, period.c_str()) : "нет " + period,
            schannel ? Level::Bad : Level::Ok,
            "Schannel 36870 - служба RDP не может открыть закрытый ключ сертификата."
            + (ts1057 > 0 ? Fmt(" Событие 1057 (%d) при старте службы безвредно, если сертификат привязан.", ts1057) : std::string()));
        if (schannel > 0) certBad = true;
    }

    // 7. Рукопожатие.
    std::string hs;
    bool hsOk = svcRunning && !rdpOff && RdpHandshake(port, hs);
    if (!svcRunning) hs = "служба не запущена";
    else if (rdpOff) hs = "подключения запрещены";
    add("Рукопожатие RDP (127.0.0.1)", hs, hsOk ? Level::Ok : Level::Bad,
        "Утилита отправляет X.224 Connection Request и ждёт Connection Confirm.");

    if (rdpOff) {
        st.verdict = Verdict::RdpDisabled;
        st.summary = "Удалённый рабочий стол выключен";
        st.details = "Включите его в параметрах Windows, затем проверьте снова.";
    } else if (!hsOk || certBad) {
        st.verdict = Verdict::CertBroken;
        st.summary = "RDP не принимает подключения";
        st.details = cp ? "Похоже на поломку сертификата из-за КриптоПро. Нажмите «Починить»."
                        : "Сертификат RDP повреждён или недоступен. Нажмите «Починить».";
    } else {
        st.verdict = Verdict::Working;
        st.summary = "RDP работает";
        st.details = "Сертификат в порядке, служба отвечает на подключения.";
    }
    return st;
}

FixResult RunFix(const LogFn& fn) {
    Logger L{ fn };
    FixResult res;
    try {
        if (!IsProcessElevated()) throw Fatal{ "нужны права администратора" };
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);

        wchar_t host[MAX_COMPUTERNAME_LENGTH + 1]; DWORD hl = MAX_COMPUTERNAME_LENGTH + 1;
        Check(GetComputerNameW(host, &hl) != FALSE, "имя компьютера", GetLastError());

        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        Check(scm != nullptr, "диспетчер служб", GetLastError());

        L.step("Остановка служб RDP");
        StopSvc(L, scm, L"UmRdpService");  // зависит от TermService, гасим первой
        StopSvc(L, scm, L"TermService");

        L.step("Удаление старых сертификатов");
        int n = PurgeStore(L, L"Remote Desktop", [](PCCERT_CONTEXT) { return true; });
        n += PurgeStore(L, L"MY", [](PCCERT_CONTEXT c) {
            std::wstring f = FriendlyName(c);
            for (const wchar_t* own : kOwnFriendlyNames) if (f == own) return true;
            return false;
        });
        if (n == 0) L.ok("удалять нечего");

        L.step("Выпуск нового сертификата");
        std::vector<BYTE> hash = IssueCertificate(L, host);
        res.thumbprint = Hex(hash.data(), 20);

        L.step("Привязка к RDP");
        HKEY k = nullptr;
        LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRdpTcpKey, 0, KEY_SET_VALUE, &k);
        Check(rc == ERROR_SUCCESS, "открытие ключа RDP-Tcp", (DWORD)rc);
        rc = RegSetValueExW(k, L"SSLCertificateSHA1Hash", 0, REG_BINARY, hash.data(), (DWORD)hash.size());
        RegCloseKey(k);
        Check(rc == ERROR_SUCCESS, "запись SSLCertificateSHA1Hash", (DWORD)rc);
        L.ok("отпечаток записан в RDP-Tcp");

        L.step("Запуск служб RDP");
        StartSvc(L, scm, L"TermService");
        StartSvc(L, scm, L"UmRdpService");
        CloseServiceHandle(scm);

        L.step("Проверка");
        DWORD port = RdpPort();
        std::string detail; bool ok = false;
        for (int i = 0; i < 10 && !ok; ++i) { Sleep(1000); ok = RdpHandshake(port, detail); }
        if (ok) L.ok(Fmt("RDP на порту %lu %s", port, detail.c_str()));
        else L.warn(Fmt("RDP на порту %lu: %s", port, detail.c_str()));

        res.ok = true;
    } catch (const Fatal& f) {
        L.bad(f.msg);
    }
    res.warnings = L.warnings;
    return res;
}
