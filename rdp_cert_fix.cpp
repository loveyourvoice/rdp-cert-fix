// rdp-cert-fix: чинит TLS-сертификат RDP, который ломает КриптоПро CSP.
//
// Симптом: RDP рвёт любое подключение сразу после X.224, в журнале System
//   TerminalServices-RemoteConnectionManager 1057 «Указан неправильный алгоритм»
//   Schannel 36870, код 0x8009030D.
// Лечение: убрать сломанные сертификаты, выпустить свой самоподписанный RSA-2048/SHA-256
// через Microsoft Software Key Storage Provider, дать NETWORK SERVICE чтение ключа,
// привязать отпечаток к RDP-Tcp и перезапустить службу.
//
// Флаги: /quiet - не ждать Enter в конце.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <sddl.h>
#include <objbase.h>
#include <fcntl.h>
#include <io.h>
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ws2_32.lib")

static const wchar_t* kFriendlyName = L"RDP (rdp-cert-fix)";
// Имена, которыми помечались сертификаты, выпущенные раньше вручную - их тоже чистим.
static const wchar_t* kOldFriendlyNames[] = { L"RDP (rdp-cert-fix)", L"RDP (manual)" };
static const wchar_t* kRdpTcpKey = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";

static int g_warnings = 0;

static void Ok(const wchar_t* fmt, ...) {
    va_list a; va_start(a, fmt); wprintf(L"  [ok] "); vwprintf(fmt, a); wprintf(L"\n"); va_end(a);
}
static void Warn(const wchar_t* fmt, ...) {
    va_list a; va_start(a, fmt); wprintf(L"  [!!] "); vwprintf(fmt, a); wprintf(L"\n"); va_end(a);
    ++g_warnings;
}
static void Step(const wchar_t* title) { wprintf(L"\n== %ls\n", title); }

static std::wstring ErrText(DWORD code) {
    wchar_t* buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring s = buf ? buf : L"";
    if (buf) LocalFree(buf);
    while (!s.empty() && (s.back() == L'\n' || s.back() == L'\r' || s.back() == L' ')) s.pop_back();
    wchar_t hex[16];
    swprintf_s(hex, L"0x%08X", code);
    return s.empty() ? hex : s + L" (" + hex + L")";
}

struct Fatal { std::wstring msg; };
static void Check(bool cond, const std::wstring& what, DWORD code) {
    if (!cond) throw Fatal{ what + L": " + ErrText(code) };
}
static void CheckNt(SECURITY_STATUS st, const std::wstring& what) {
    if (st != ERROR_SUCCESS) throw Fatal{ what + L": " + ErrText((DWORD)st) };
}

static bool IsElevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{}; DWORD len = 0;
    BOOL ok = GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &len);
    CloseHandle(tok);
    return ok && el.TokenIsElevated;
}

// ---------- службы ----------

static bool WaitSvc(SC_HANDLE s, DWORD want, DWORD timeoutMs) {
    SERVICE_STATUS st{};
    for (DWORD t = 0; t < timeoutMs; t += 250) {
        if (!QueryServiceStatus(s, &st)) return false;
        if (st.dwCurrentState == want) return true;
        Sleep(250);
    }
    return false;
}

static void StopSvc(SC_HANDLE scm, const wchar_t* name) {
    SC_HANDLE s = OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!s) { Warn(L"служба %ls не открылась: %ls", name, ErrText(GetLastError()).c_str()); return; }
    SERVICE_STATUS st{};
    QueryServiceStatus(s, &st);
    if (st.dwCurrentState != SERVICE_STOPPED) {
        if (!ControlService(s, SERVICE_CONTROL_STOP, &st) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
            Warn(L"%ls не останавливается: %ls", name, ErrText(GetLastError()).c_str());
        else if (!WaitSvc(s, SERVICE_STOPPED, 30000))
            Warn(L"%ls не остановилась за 30 с", name);
        else
            Ok(L"%ls остановлена", name);
    } else {
        Ok(L"%ls уже остановлена", name);
    }
    CloseServiceHandle(s);
}

static void StartSvc(SC_HANDLE scm, const wchar_t* name, bool required) {
    SC_HANDLE s = OpenServiceW(scm, name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!s) {
        if (required) Warn(L"служба %ls не открылась: %ls", name, ErrText(GetLastError()).c_str());
        return;
    }
    if (!StartServiceW(s, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        Warn(L"%ls не запускается: %ls", name, ErrText(GetLastError()).c_str());
    else if (!WaitSvc(s, SERVICE_RUNNING, 30000))
        Warn(L"%ls не запустилась за 30 с", name);
    else
        Ok(L"%ls запущена", name);
    CloseServiceHandle(s);
}

// ---------- сертификаты ----------

static std::wstring GetFriendlyName(PCCERT_CONTEXT c) {
    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(c, CERT_FRIENDLY_NAME_PROP_ID, nullptr, &cb) || cb < sizeof(wchar_t))
        return L"";
    std::wstring s(cb / sizeof(wchar_t), L'\0');
    CertGetCertificateContextProperty(c, CERT_FRIENDLY_NAME_PROP_ID, &s[0], &cb);
    while (!s.empty() && s.back() == L'\0') s.pop_back();
    return s;
}

static std::wstring Thumbprint(PCCERT_CONTEXT c) {
    BYTE h[20]; DWORD cb = sizeof(h);
    if (!CertGetCertificateContextProperty(c, CERT_SHA1_HASH_PROP_ID, h, &cb)) return L"?";
    std::wstring s;
    wchar_t b[3];
    for (DWORD i = 0; i < cb; ++i) { swprintf_s(b, L"%02X", h[i]); s += b; }
    return s;
}

// Удаляет закрытый ключ, на который ссылается сертификат (CNG или старый CAPI).
static void DeletePrivateKey(PCCERT_CONTEXT c) {
    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &cb)) return;
    std::vector<BYTE> buf(cb);
    auto* kpi = reinterpret_cast<CRYPT_KEY_PROV_INFO*>(buf.data());
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, kpi, &cb)) return;

    bool machine = (kpi->dwFlags & CRYPT_MACHINE_KEYSET) != 0;
    if (kpi->dwProvType == 0) {
        NCRYPT_PROV_HANDLE prov = 0; NCRYPT_KEY_HANDLE key = 0;
        SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, kpi->pwszProvName, 0);
        if (st == ERROR_SUCCESS)
            st = NCryptOpenKey(prov, &key, kpi->pwszContainerName, 0, machine ? NCRYPT_MACHINE_KEY_FLAG : 0);
        if (st == ERROR_SUCCESS)
            st = NCryptDeleteKey(key, 0);  // освобождает key и при успехе
        if (prov) NCryptFreeObject(prov);
        if (st == ERROR_SUCCESS) Ok(L"ключ %ls удалён", kpi->pwszContainerName);
        else Warn(L"ключ %ls не удалён: %ls", kpi->pwszContainerName, ErrText((DWORD)st).c_str());
    } else {
        HCRYPTPROV h = 0;
        if (CryptAcquireContextW(&h, kpi->pwszContainerName, kpi->pwszProvName, kpi->dwProvType,
                                 CRYPT_DELETEKEYSET | (machine ? CRYPT_MACHINE_KEYSET : 0)))
            Ok(L"ключ %ls удалён", kpi->pwszContainerName);
        else
            Warn(L"ключ %ls не удалён: %ls", kpi->pwszContainerName, ErrText(GetLastError()).c_str());
    }
}

// Удаляет из хранилища LocalMachine\<storeName> сертификаты, подходящие под фильтр, вместе с ключами.
template <class Pred>
static int PurgeStore(const wchar_t* storeName, Pred match) {
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, storeName);
    if (!store) return 0;
    std::vector<PCCERT_CONTEXT> victims;
    PCCERT_CONTEXT c = nullptr;
    while ((c = CertEnumCertificatesInStore(store, c)) != nullptr)
        if (match(c)) victims.push_back(CertDuplicateCertificateContext(c));
    for (PCCERT_CONTEXT v : victims) {
        std::wstring tp = Thumbprint(v);
        DeletePrivateKey(v);
        if (CertDeleteCertificateFromStore(v))  // освобождает v
            Ok(L"сертификат %ls удалён из %ls", tp.c_str(), storeName);
        else
            Warn(L"сертификат %ls не удалён: %ls", tp.c_str(), ErrText(GetLastError()).c_str());
    }
    CertCloseStore(store, 0);
    return (int)victims.size();
}

struct Encoded {
    BYTE* data = nullptr; DWORD size = 0;
    ~Encoded() { if (data) LocalFree(data); }
};
static void Encode(LPCSTR type, const void* obj, Encoded& out, const wchar_t* what) {
    Check(CryptEncodeObjectEx(X509_ASN_ENCODING, type, obj, CRYPT_ENCODE_ALLOC_FLAG, nullptr, &out.data, &out.size) != FALSE,
          std::wstring(L"кодирование ") + what, GetLastError());
}

static std::wstring NewKeyName() {
    GUID g{}; CoCreateGuid(&g);
    wchar_t s[64]; StringFromGUID2(g, s, 64);
    return std::wstring(L"rdp-cert-fix-") + s;
}

// Выпускает сертификат, кладёт в LocalMachine\My, возвращает SHA1-отпечаток.
static std::vector<BYTE> IssueCertificate(const std::wstring& host) {
    NCRYPT_PROV_HANDLE prov = 0; NCRYPT_KEY_HANDLE key = 0;
    CheckNt(NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0), L"открытие Microsoft Software KSP");
    std::wstring keyName = NewKeyName();
    CheckNt(NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM, keyName.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG),
            L"создание ключа");
    DWORD len = 2048, exportPolicy = 0, usage = NCRYPT_ALLOW_ALL_USAGES;
    CheckNt(NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&len, sizeof(len), 0), L"длина ключа");
    CheckNt(NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&exportPolicy, sizeof(exportPolicy), 0), L"политика экспорта");
    CheckNt(NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&usage, sizeof(usage), 0), L"назначение ключа");
    CheckNt(NCryptFinalizeKey(key, 0), L"генерация ключа");
    Ok(L"ключ RSA-2048 %ls создан", keyName.c_str());

    // SYSTEM и администраторы - полный доступ, NETWORK SERVICE (под ней TermService) - чтение.
    PSECURITY_DESCRIPTOR sd = nullptr; ULONG sdLen = 0;
    Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;NS)",
                                                               SDDL_REVISION_1, &sd, &sdLen) != FALSE,
          L"SDDL", GetLastError());
    SECURITY_STATUS st = NCryptSetProperty(key, NCRYPT_SECURITY_DESCR_PROPERTY, (PBYTE)sd, sdLen, DACL_SECURITY_INFORMATION);
    LocalFree(sd);
    CheckNt(st, L"права на ключ для NETWORK SERVICE");
    Ok(L"NETWORK SERVICE получила чтение ключа");

    // Субъект и расширения.
    std::wstring subject = L"CN=" + host;
    DWORD nameLen = 0;
    Check(CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR, nullptr, nullptr, &nameLen, nullptr) != FALSE,
          L"имя субъекта", GetLastError());
    std::vector<BYTE> nameBuf(nameLen);
    Check(CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR, nullptr, nameBuf.data(), &nameLen, nullptr) != FALSE,
          L"имя субъекта", GetLastError());
    CERT_NAME_BLOB subj{ nameLen, nameBuf.data() };

    LPSTR ekuOid = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
    CERT_ENHKEY_USAGE eku{ 1, &ekuOid };
    Encoded ekuEnc; Encode(X509_ENHANCED_KEY_USAGE, &eku, ekuEnc, L"EKU");

    BYTE kuBits = CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE;
    CRYPT_BIT_BLOB ku{ 1, &kuBits, 0 };
    Encoded kuEnc; Encode(X509_KEY_USAGE, &ku, kuEnc, L"KeyUsage");

    CERT_ALT_NAME_ENTRY san{}; san.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; san.pwszDNSName = (LPWSTR)host.c_str();
    CERT_ALT_NAME_INFO sanInfo{ 1, &san };
    Encoded sanEnc; Encode(X509_ALTERNATE_NAME, &sanInfo, sanEnc, L"SAN");

    CERT_EXTENSION ext[3] = {
        { (LPSTR)szOID_ENHANCED_KEY_USAGE, FALSE, { ekuEnc.size, ekuEnc.data } },
        { (LPSTR)szOID_KEY_USAGE, TRUE, { kuEnc.size, kuEnc.data } },
        { (LPSTR)szOID_SUBJECT_ALT_NAME2, FALSE, { sanEnc.size, sanEnc.data } },
    };
    CERT_EXTENSIONS exts{ 3, ext };

    CRYPT_KEY_PROV_INFO kpi{};
    kpi.pwszContainerName = (LPWSTR)keyName.c_str();
    kpi.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
    kpi.dwProvType = 0;                    // 0 = CNG
    kpi.dwFlags = NCRYPT_MACHINE_KEY_FLAG;
    kpi.dwKeySpec = 0;

    CRYPT_ALGORITHM_IDENTIFIER alg{ (LPSTR)szOID_RSA_SHA256RSA, {} };

    SYSTEMTIME now; GetSystemTime(&now);
    FILETIME ft; SystemTimeToFileTime(&now, &ft);
    ULARGE_INTEGER u{ ft.dwLowDateTime, ft.dwHighDateTime };
    const ULONGLONG day = 864000000000ULL;  // 100-нс интервалов в сутках
    ULARGE_INTEGER b = u, e = u;
    b.QuadPart -= day;
    e.QuadPart += day * 3652;              // ~10 лет
    FILETIME fb{ b.LowPart, b.HighPart }, fe{ e.LowPart, e.HighPart };
    SYSTEMTIME start, end;
    FileTimeToSystemTime(&fb, &start); FileTimeToSystemTime(&fe, &end);

    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(key, &subj, 0, &kpi, &alg, &start, &end, &exts);
    Check(cert != nullptr, L"выпуск сертификата", GetLastError());

    HCERTSTORE my = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
    Check(my != nullptr, L"открытие LocalMachine\\My", GetLastError());
    PCCERT_CONTEXT added = nullptr;
    Check(CertAddCertificateContextToStore(my, cert, CERT_STORE_ADD_NEW, &added) != FALSE,
          L"сохранение в LocalMachine\\My", GetLastError());
    CRYPT_DATA_BLOB fn{ (DWORD)((wcslen(kFriendlyName) + 1) * sizeof(wchar_t)), (BYTE*)kFriendlyName };
    CertSetCertificateContextProperty(added, CERT_FRIENDLY_NAME_PROP_ID, 0, &fn);

    // Самопроверка: ключ сертификата действительно открывается.
    NCRYPT_KEY_HANDLE probe = 0; DWORD spec = 0; BOOL mustFree = FALSE;
    if (CryptAcquireCertificatePrivateKey(added, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                                          nullptr, &probe, &spec, &mustFree)) {
        if (mustFree) NCryptFreeObject(probe);
    } else {
        Warn(L"ключ сертификата не открывается: %ls", ErrText(GetLastError()).c_str());
    }

    std::vector<BYTE> hash(20); DWORD cb = 20;
    CertGetCertificateContextProperty(added, CERT_SHA1_HASH_PROP_ID, hash.data(), &cb);
    Ok(L"сертификат CN=%ls выпущен, отпечаток %ls, до %04u-%02u-%02u",
       host.c_str(), Thumbprint(added).c_str(), end.wYear, end.wMonth, end.wDay);

    CertFreeCertificateContext(added);
    CertFreeCertificateContext(cert);
    CertCloseStore(my, 0);
    NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return hash;
}

static void BindToRdp(const std::vector<BYTE>& hash) {
    HKEY k = nullptr;
    LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRdpTcpKey, 0, KEY_SET_VALUE, &k);
    Check(rc == ERROR_SUCCESS, L"открытие ключа RDP-Tcp", (DWORD)rc);
    rc = RegSetValueExW(k, L"SSLCertificateSHA1Hash", 0, REG_BINARY, hash.data(), (DWORD)hash.size());
    RegCloseKey(k);
    Check(rc == ERROR_SUCCESS, L"запись SSLCertificateSHA1Hash", (DWORD)rc);
    Ok(L"отпечаток записан в RDP-Tcp\\SSLCertificateSHA1Hash");
}

static DWORD RdpPort() {
    HKEY k = nullptr; DWORD port = 3389, cb = sizeof(port), type = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRdpTcpKey, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"PortNumber", nullptr, &type, (LPBYTE)&port, &cb) != ERROR_SUCCESS || type != REG_DWORD)
            port = 3389;
        RegCloseKey(k);
    }
    return port;
}

// Отправляет X.224 Connection Request на localhost и ждёт Connection Confirm (0xD0).
static void SelfTest() {
    DWORD port = RdpPort();
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) { Warn(L"Winsock не стартовал"); return; }
    bool okResult = false; std::wstring detail;
    for (int attempt = 0; attempt < 10 && !okResult; ++attempt) {
        Sleep(1000);
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        DWORD tmo = 5000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons((u_short)port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (connect(s, (sockaddr*)&a, sizeof(a)) != 0) {
            detail = L"порт не принимает подключения";
            closesocket(s); continue;
        }
        static const unsigned char cr[] = { 0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,
                                            0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00 };
        send(s, (const char*)cr, sizeof(cr), 0);
        unsigned char resp[64]; int n = recv(s, (char*)resp, sizeof(resp), 0);
        closesocket(s);
        if (n >= 6 && resp[0] == 0x03 && resp[5] == 0xD0) okResult = true;
        else detail = n > 0 ? L"неожиданный ответ" : L"соединение закрыто без ответа";
    }
    WSACleanup();
    if (okResult) Ok(L"RDP на 127.0.0.1:%lu отвечает на рукопожатие", port);
    else Warn(L"RDP на 127.0.0.1:%lu не ответил (%ls) - см. журнал System, события Schannel/TerminalServices",
              port, detail.c_str());
}

int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    bool quiet = false;
    for (int i = 1; i < argc; ++i)
        if (!_wcsicmp(argv[i], L"/quiet") || !_wcsicmp(argv[i], L"-quiet")) quiet = true;

    wprintf(L"rdp-cert-fix: перевыпуск сертификата RDP (обход поломки от КриптоПро)\n");
    int rc = 0;
    try {
        if (!IsElevated()) throw Fatal{ L"нужны права администратора (запустите через «Запуск от имени администратора»)" };
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);

        wchar_t host[MAX_COMPUTERNAME_LENGTH + 1]; DWORD hl = MAX_COMPUTERNAME_LENGTH + 1;
        Check(GetComputerNameW(host, &hl) != FALSE, L"имя компьютера", GetLastError());

        wprintf(L"\nВнимание: служба RDP будет перезапущена, активные RDP-сеансы отключатся\n"
                L"(сеансы не завершаются, к ним можно переподключиться).\n");

        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        Check(scm != nullptr, L"диспетчер служб", GetLastError());

        Step(L"Остановка служб RDP");
        StopSvc(scm, L"UmRdpService");   // зависит от TermService, гасим первой
        StopSvc(scm, L"TermService");

        Step(L"Удаление старых сертификатов");
        int n = PurgeStore(L"Remote Desktop", [](PCCERT_CONTEXT) { return true; });
        n += PurgeStore(L"MY", [](PCCERT_CONTEXT c) {
            std::wstring fn = GetFriendlyName(c);
            for (const wchar_t* old : kOldFriendlyNames) if (fn == old) return true;
            return false;
        });
        if (n == 0) Ok(L"удалять нечего");

        Step(L"Выпуск нового сертификата");
        std::vector<BYTE> hash = IssueCertificate(host);

        Step(L"Привязка к RDP");
        BindToRdp(hash);

        Step(L"Запуск служб RDP");
        StartSvc(scm, L"TermService", true);
        StartSvc(scm, L"UmRdpService", false);
        CloseServiceHandle(scm);

        Step(L"Проверка");
        SelfTest();

        wprintf(g_warnings ? L"\nГотово, но с предупреждениями: %d.\n" : L"\nГотово, RDP должен работать.\n", g_warnings);
        rc = g_warnings ? 2 : 0;
    } catch (const Fatal& f) {
        wprintf(L"\n  [ОШИБКА] %ls\n", f.msg.c_str());
        rc = 1;
    }
    if (!quiet) { wprintf(L"\nНажмите Enter для выхода..."); getwchar(); }
    return rc;
}
