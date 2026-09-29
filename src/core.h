// Диагностика и ремонт TLS-сертификата RDP. Все строки - UTF-8.
#pragma once
#include <functional>
#include <string>
#include <vector>

#define APP_VERSION "1.0.0"

enum class Level { Ok, Info, Warn, Bad };

struct CheckItem {
    std::string title;
    std::string value;
    std::string hint;   // пояснение при наведении
    Level level = Level::Info;
};

enum class Verdict { Working, CertBroken, RdpDisabled };

struct Status {
    std::vector<CheckItem> items;
    Verdict verdict = Verdict::Working;
    std::string summary;
    std::string details;
};

struct LogLine {
    Level level = Level::Info;
    std::string text;
    bool step = false;  // заголовок шага
};
using LogFn = std::function<void(const LogLine&)>;

struct FixResult {
    bool ok = false;        // без фатальных ошибок
    int warnings = 0;
    std::string thumbprint; // отпечаток нового сертификата
};

bool IsProcessElevated();
Status RunChecks();
FixResult RunFix(const LogFn& log);
