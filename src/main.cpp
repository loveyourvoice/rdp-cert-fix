// RDP Cert Fix - окно на Dear ImGui + DX11.
//
// Ключи командной строки (без окна):
//   /check  - только проверка; код возврата 0 - RDP работает, 3 - сломан, 4 - RDP выключен
//   /fix    - ремонт; код возврата 0 - успех, 2 - с предупреждениями, 1 - ошибка
// Журнал пишется в %TEMP%\rdp-cert-fix.log.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d11.h>
#include <dwmapi.h>
#include <wincodec.h>
#include <shellapi.h>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"

#include "core.h"
#include "../res/resource.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "shell32.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace {

// ---------- палитра (светлая, под иконку) ----------

constexpr ImU32 RGBc(int r, int g, int b, int a = 255) { return IM_COL32(r, g, b, a); }
const ImU32 cBg        = RGBc(244, 246, 250);
const ImU32 cCard      = RGBc(255, 255, 255);
const ImU32 cBorder    = RGBc(227, 232, 240);
const ImU32 cText      = RGBc(27, 36, 48);
const ImU32 cMuted     = RGBc(107, 118, 134);
const ImU32 cAccent    = RGBc(23, 102, 229);
const ImU32 cAccentHov = RGBc(18, 88, 204);
const ImU32 cAccentAct = RGBc(14, 74, 176);
const ImU32 cOk        = RGBc(30, 158, 90);
const ImU32 cWarn      = RGBc(224, 138, 0);
const ImU32 cBad       = RGBc(224, 52, 42);
const ImU32 cInfo      = RGBc(120, 132, 150);
const ImU32 cOkSoft    = RGBc(232, 246, 238);
const ImU32 cBadSoft   = RGBc(253, 236, 234);
const ImU32 cWarnSoft  = RGBc(255, 244, 224);
const ImU32 cNeutral   = RGBc(236, 240, 246);

ImVec4 V(ImU32 c) { return ImGui::ColorConvertU32ToFloat4(c); }

ImU32 LevelColor(Level l) {
    switch (l) {
    case Level::Ok: return cOk;
    case Level::Warn: return cWarn;
    case Level::Bad: return cBad;
    default: return cInfo;
    }
}

// ---------- D3D ----------

ID3D11Device* g_dev = nullptr;
ID3D11DeviceContext* g_ctx = nullptr;
IDXGISwapChain* g_swap = nullptr;
ID3D11RenderTargetView* g_rtv = nullptr;
UINT g_resizeW = 0, g_resizeH = 0;
bool g_dpiChanged = false;
float g_scale = 1.0f;

void CreateRT() {
    ID3D11Texture2D* back = nullptr;
    g_swap->GetBuffer(0, IID_PPV_ARGS(&back));
    g_dev->CreateRenderTargetView(back, nullptr, &g_rtv);
    back->Release();
}
void DestroyRT() { if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; } }

bool CreateDevice(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL got;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2,
                                               D3D11_SDK_VERSION, &sd, &g_swap, &g_dev, &got, &g_ctx);
    if (hr == DXGI_ERROR_UNSUPPORTED)  // нет GPU (виртуалка, RDP без адаптера) - программный растеризатор
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2,
                                           D3D11_SDK_VERSION, &sd, &g_swap, &g_dev, &got, &g_ctx);
    if (FAILED(hr)) return false;
    CreateRT();
    return true;
}

void DestroyDevice() {
    DestroyRT();
    if (g_swap) g_swap->Release();
    if (g_ctx) g_ctx->Release();
    if (g_dev) g_dev->Release();
}

// Иконка из ресурсов (PNG) -> текстура.
ID3D11ShaderResourceView* LoadPngResource(int id, int& w, int& h) {
    HRSRC r = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!r) return nullptr;
    HGLOBAL g = LoadResource(nullptr, r);
    const BYTE* data = (const BYTE*)LockResource(g);
    DWORD size = SizeofResource(nullptr, r);

    IWICImagingFactory* f = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&f)))) return nullptr;
    IWICStream* s = nullptr; IWICBitmapDecoder* dec = nullptr; IWICBitmapFrameDecode* fr = nullptr; IWICFormatConverter* cv = nullptr;
    ID3D11ShaderResourceView* srv = nullptr;
    if (SUCCEEDED(f->CreateStream(&s)) && SUCCEEDED(s->InitializeFromMemory((BYTE*)data, size)) &&
        SUCCEEDED(f->CreateDecoderFromStream(s, nullptr, WICDecodeMetadataCacheOnLoad, &dec)) &&
        SUCCEEDED(dec->GetFrame(0, &fr)) && SUCCEEDED(f->CreateFormatConverter(&cv)) &&
        SUCCEEDED(cv->Initialize(fr, GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone, nullptr, 0, WICBitmapPaletteTypeCustom))) {
        UINT uw, uh; cv->GetSize(&uw, &uh);
        std::vector<BYTE> px(uw * uh * 4);
        cv->CopyPixels(nullptr, uw * 4, (UINT)px.size(), px.data());
        D3D11_TEXTURE2D_DESC td{};
        td.Width = uw; td.Height = uh; td.MipLevels = 1; td.ArraySize = 1;
        td.Format = DXGI_FORMAT_R8G8B8A8_UNORM; td.SampleDesc.Count = 1;
        td.Usage = D3D11_USAGE_DEFAULT; td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        D3D11_SUBRESOURCE_DATA sub{ px.data(), uw * 4, 0 };
        ID3D11Texture2D* tex = nullptr;
        if (SUCCEEDED(g_dev->CreateTexture2D(&td, &sub, &tex))) {
            g_dev->CreateShaderResourceView(tex, nullptr, &srv);
            tex->Release();
        }
        w = (int)uw; h = (int)uh;
    }
    if (cv) cv->Release(); if (fr) fr->Release(); if (dec) dec->Release(); if (s) s->Release();
    f->Release();
    return srv;
}

// ---------- шрифты и стиль ----------

ImFont* fBody = nullptr;
ImFont* fSemi = nullptr;
ImFont* fTitle = nullptr;
ImFont* fBanner = nullptr;
ImFont* fSmall = nullptr;
ImVector<ImWchar> g_ranges;

void BuildFonts(float scale) {
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
    if (g_ranges.empty()) {
        ImFontGlyphRangesBuilder b;
        b.AddRanges(io.Fonts->GetGlyphRangesCyrillic());
        static const ImWchar extra[] = { 0x2010, 0x205E, 0x2190, 0x21FF, 0x2116, 0x2116, 0 };  // пунктуация, стрелки, №
        b.AddRanges(extra);
        b.BuildRanges(&g_ranges);
    }
    wchar_t win[MAX_PATH]; GetWindowsDirectoryW(win, MAX_PATH);
    auto path = [&](const char* file) {
        char p[MAX_PATH * 2];
        WideCharToMultiByte(CP_UTF8, 0, win, -1, p, sizeof(p), nullptr, nullptr);
        return std::string(p) + "\\Fonts\\" + file;
    };
    auto load = [&](const char* file, const char* fallback, float size) -> ImFont* {
        ImFontConfig cfg; cfg.OversampleH = 2; cfg.OversampleV = 1; cfg.PixelSnapH = false;
        for (const char* f : { file, fallback }) {
            std::string p = path(f);
            if (GetFileAttributesA(p.c_str()) != INVALID_FILE_ATTRIBUTES)
                return io.Fonts->AddFontFromFileTTF(p.c_str(), size * scale, &cfg, g_ranges.Data);
        }
        cfg.SizePixels = size * scale;
        return io.Fonts->AddFontDefault(&cfg);
    };
    fBody = load("segoeui.ttf", "arial.ttf", 16.0f);
    fSemi = load("seguisb.ttf", "segoeuib.ttf", 16.0f);
    fTitle = load("seguisb.ttf", "segoeuib.ttf", 25.0f);
    fBanner = load("seguisb.ttf", "segoeuib.ttf", 19.0f);
    fSmall = load("segoeui.ttf", "arial.ttf", 13.5f);
    io.FontDefault = fBody;
}

void ApplyStyle(float scale) {
    ImGuiStyle st;
    ImGui::StyleColorsLight(&st);
    st.WindowPadding = ImVec2(24, 22);
    st.FramePadding = ImVec2(12, 8);
    st.ItemSpacing = ImVec2(12, 10);
    st.WindowRounding = 0;
    st.ChildRounding = 14;
    st.FrameRounding = 10;
    st.PopupRounding = 10;
    st.ScrollbarRounding = 8;
    st.ScrollbarSize = 10;
    st.ChildBorderSize = 1;
    st.WindowBorderSize = 0;
    st.PopupBorderSize = 1;
    ImVec4* c = st.Colors;
    c[ImGuiCol_WindowBg] = V(cBg);
    c[ImGuiCol_ChildBg] = V(cCard);
    c[ImGuiCol_PopupBg] = V(cCard);
    c[ImGuiCol_Border] = V(cBorder);
    c[ImGuiCol_Text] = V(cText);
    c[ImGuiCol_TextDisabled] = V(cMuted);
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = V(RGBc(205, 212, 224));
    c[ImGuiCol_ScrollbarGrabHovered] = V(RGBc(180, 190, 206));
    c[ImGuiCol_ScrollbarGrabActive] = V(RGBc(160, 172, 190));
    c[ImGuiCol_TextSelectedBg] = V(RGBc(23, 102, 229, 60));
    st.ScaleAllSizes(scale);
    ImGui::GetStyle() = st;
}

// ---------- состояние приложения ----------

struct AppState {
    std::mutex mu;
    std::optional<Status> status;
    std::vector<LogLine> log;
    std::optional<FixResult> fix;
    std::atomic<bool> checking{ false };
    std::atomic<bool> fixing{ false };
    std::string checkedAt;
    bool logScrollToEnd = false;
};
AppState g_app;

std::string NowStr() {
    time_t t = time(nullptr); tm lt; localtime_s(&lt, &t);
    char b[16]; strftime(b, sizeof(b), "%H:%M:%S", &lt);
    return b;
}

void StartChecks() {
    if (g_app.checking.exchange(true)) return;
    std::thread([] {
        Status s = RunChecks();
        {
            std::lock_guard<std::mutex> lk(g_app.mu);
            g_app.status = std::move(s);
            g_app.checkedAt = NowStr();
        }
        g_app.checking = false;
    }).detach();
}

void StartFix() {
    if (g_app.fixing.exchange(true)) return;
    {
        std::lock_guard<std::mutex> lk(g_app.mu);
        g_app.log.clear();
        g_app.fix.reset();
    }
    std::thread([] {
        FixResult r = RunFix([](const LogLine& l) {
            std::lock_guard<std::mutex> lk(g_app.mu);
            g_app.log.push_back(l);
            g_app.logScrollToEnd = true;
        });
        {
            std::lock_guard<std::mutex> lk(g_app.mu);
            g_app.fix = r;
            g_app.status.reset();  // до перепроверки показываем «Проверяем…», а не старый вердикт
        }
        g_app.fixing = false;
        // После ремонта сразу перепроверяем.
        while (g_app.checking) Sleep(50);
        StartChecks();
    }).detach();
}

// ---------- рисование ----------

float S(float v) { return v * g_scale; }

void DrawCheck(ImDrawList* d, ImVec2 c, float r, ImU32 col, float th) {
    d->PathLineTo(ImVec2(c.x - r * 0.45f, c.y + r * 0.02f));
    d->PathLineTo(ImVec2(c.x - r * 0.12f, c.y + r * 0.34f));
    d->PathLineTo(ImVec2(c.x + r * 0.48f, c.y - r * 0.32f));
    d->PathStroke(col, 0, th);
}

void DrawStatusIcon(ImDrawList* d, ImVec2 c, float r, Level l) {
    ImU32 col = LevelColor(l);
    d->AddCircleFilled(c, r, col, 32);
    const ImU32 w = IM_COL32_WHITE;
    float th = std::max(1.5f, r * 0.22f);
    switch (l) {
    case Level::Ok:
        DrawCheck(d, c, r, w, th);
        break;
    case Level::Bad: {
        float k = r * 0.36f;
        d->AddLine(ImVec2(c.x - k, c.y - k), ImVec2(c.x + k, c.y + k), w, th);
        d->AddLine(ImVec2(c.x + k, c.y - k), ImVec2(c.x - k, c.y + k), w, th);
        break;
    }
    case Level::Warn:
        d->AddLine(ImVec2(c.x, c.y - r * 0.48f), ImVec2(c.x, c.y + r * 0.12f), w, th);
        d->AddCircleFilled(ImVec2(c.x, c.y + r * 0.42f), th * 0.6f, w);
        break;
    default:
        d->AddCircleFilled(ImVec2(c.x, c.y - r * 0.42f), th * 0.6f, w);
        d->AddLine(ImVec2(c.x, c.y - r * 0.1f), ImVec2(c.x, c.y + r * 0.5f), w, th);
        break;
    }
}

void DrawSpinner(ImDrawList* d, ImVec2 c, float r, ImU32 col, float th) {
    float t = (float)ImGui::GetTime();
    float a0 = t * 6.0f;
    float a1 = a0 + IM_PI * (0.9f + 0.5f * sinf(t * 2.3f));
    d->PathArcTo(c, r, a0, a1, 32);
    d->PathStroke(col, 0, th);
}

// Текст справа в пределах строки.
void TextRight(ImDrawList* d, ImFont* f, float right, float y, ImU32 col, const std::string& s) {
    ImVec2 sz = f->CalcTextSizeA(f->FontSize, FLT_MAX, 0, s.c_str());
    d->AddText(f, f->FontSize, ImVec2(right - sz.x, y), col, s.c_str());
}

enum class BtnKind { Primary, Secondary };

bool Button(const char* id, const std::string& label, ImVec2 size, BtnKind kind, bool enabled, bool busy = false) {
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool pressed = ImGui::InvisibleButton("##b", size, ImGuiButtonFlags_None) && enabled;
    bool hov = ImGui::IsItemHovered() && enabled;
    bool act = ImGui::IsItemActive() && enabled;
    if (hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    ImDrawList* d = ImGui::GetWindowDrawList();
    ImVec2 q(p.x + size.x, p.y + size.y);
    float rr = S(11);
    ImU32 bg, fg, border = 0;
    if (kind == BtnKind::Primary) {
        bg = !enabled ? RGBc(23, 102, 229, busy ? 200 : 110) : act ? cAccentAct : hov ? cAccentHov : cAccent;
        fg = IM_COL32_WHITE;
    } else {
        bg = !enabled ? cCard : act ? RGBc(228, 234, 243) : hov ? RGBc(240, 244, 250) : cCard;
        fg = enabled ? cText : cMuted;
        border = cBorder;
    }
    if (kind == BtnKind::Primary && enabled)  // мягкая тень
        d->AddRectFilled(ImVec2(p.x, p.y + S(3)), ImVec2(q.x, q.y + S(3)), RGBc(23, 102, 229, 40), rr);
    d->AddRectFilled(p, q, bg, rr);
    if (border) d->AddRect(p, q, border, rr, 0, S(1));
    ImFont* f = fSemi;
    ImVec2 ts = f->CalcTextSizeA(f->FontSize, FLT_MAX, 0, label.c_str());
    float spin = busy ? S(16) + S(10) : 0;
    float x = p.x + (size.x - ts.x - spin) * 0.5f;
    float y = p.y + (size.y - ts.y) * 0.5f;
    if (busy) {
        DrawSpinner(d, ImVec2(x + S(8), p.y + size.y * 0.5f), S(7), fg, S(2));
        x += spin;
    }
    d->AddText(f, f->FontSize, ImVec2(x, y), fg, label.c_str());
    ImGui::PopID();
    return pressed;
}

// Карточка: белый прямоугольник с рамкой. Возвращает true, если нужно рисовать содержимое.
bool BeginCard(const char* id, ImVec2 size, bool scroll = false) {
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(20), S(16)));
    bool open = ImGui::BeginChild(id, size, ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding,
                                  scroll ? 0 : (ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse));
    ImGui::PopStyleVar();
    return open;
}
void EndCard() { ImGui::EndChild(); }

void CardTitle(const char* title, const std::string& right = {}) {
    ImGui::PushFont(fSemi);
    ImGui::TextUnformatted(title);
    ImGui::PopFont();
    if (!right.empty()) {
        ImDrawList* d = ImGui::GetWindowDrawList();
        ImVec2 min = ImGui::GetItemRectMin();
        float r = ImGui::GetWindowPos().x + ImGui::GetWindowWidth() - S(20);
        TextRight(d, fSmall, r, min.y + (fSemi->FontSize - fSmall->FontSize) * 0.5f + S(1), cMuted, right);
    }
}

// ---------- экран ----------

ID3D11ShaderResourceView* g_icon = nullptr;

void DrawHeader() {
    ImDrawList* d = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float icon = S(60);
    if (g_icon) d->AddImage((ImTextureID)g_icon, p, ImVec2(p.x + icon, p.y + icon));
    float x = p.x + icon + S(16);
    d->AddText(fTitle, fTitle->FontSize, ImVec2(x, p.y + S(4)), cText, "RDP Cert Fix");
    d->AddText(fBody, fBody->FontSize, ImVec2(x, p.y + S(4) + fTitle->FontSize + S(2)), cMuted,
               "Восстановление сертификата удалённого рабочего стола при КриптоПро");
    // бейдж версии
    std::string ver = "v" APP_VERSION;
    ImVec2 ts = fSmall->CalcTextSizeA(fSmall->FontSize, FLT_MAX, 0, ver.c_str());
    float right = ImGui::GetWindowPos().x + ImGui::GetWindowWidth() - ImGui::GetStyle().WindowPadding.x;
    ImVec2 b0(right - ts.x - S(20), p.y + S(8)), b1(right, p.y + S(8) + ts.y + S(8));
    d->AddRectFilled(b0, b1, cNeutral, S(20));
    d->AddText(fSmall, fSmall->FontSize, ImVec2(b0.x + S(10), b0.y + S(4)), cMuted, ver.c_str());
    ImGui::Dummy(ImVec2(0, icon));
}

void DrawBanner(const std::optional<Status>& st, bool checking, bool fixing) {
    ImDrawList* d = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x, h = S(82);
    ImVec2 q(p.x + w, p.y + h);

    ImU32 bg = cNeutral, accent = cInfo;
    std::string title, sub;
    Level lvl = Level::Info;
    bool spinner = false;
    if (fixing) {
        title = "Идёт ремонт…"; sub = "Служба RDP перезапускается, активные RDP-сеансы на время отключатся.";
        spinner = true; accent = cAccent;
    } else if (!st) {
        title = "Проверяем…"; sub = "Собираем состояние RDP, сертификата и журнала событий.";
        spinner = true; accent = cAccent;
    } else {
        title = st->summary; sub = st->details;
        switch (st->verdict) {
        case Verdict::Working: bg = cOkSoft; accent = cOk; lvl = Level::Ok; break;
        case Verdict::CertBroken: bg = cBadSoft; accent = cBad; lvl = Level::Bad; break;
        case Verdict::RdpDisabled: bg = cWarnSoft; accent = cWarn; lvl = Level::Warn; break;
        }
    }
    d->AddRectFilled(p, q, bg, S(14));
    d->AddRectFilled(p, ImVec2(p.x + S(5), q.y), accent, S(14), ImDrawFlags_RoundCornersLeft);
    ImVec2 c(p.x + S(44), p.y + h * 0.5f);
    if (spinner) {
        d->AddCircleFilled(c, S(19), RGBc(255, 255, 255, 180), 40);
        DrawSpinner(d, c, S(11), accent, S(3));
    } else {
        DrawStatusIcon(d, c, S(19), lvl);
    }
    float tx = p.x + S(78);
    float ty = p.y + (h - fBanner->FontSize - S(4) - fBody->FontSize) * 0.5f;
    d->AddText(fBanner, fBanner->FontSize, ImVec2(tx, ty), cText, title.c_str());
    d->AddText(fBody, fBody->FontSize, ImVec2(tx, ty + fBanner->FontSize + S(4)), cMuted, sub.c_str());
    if (checking && st && !fixing) {  // тихая перепроверка
        DrawSpinner(d, ImVec2(q.x - S(22), p.y + S(22)), S(7), accent, S(2));
    }
    ImGui::Dummy(ImVec2(w, h));
}

void DrawChecks(const std::optional<Status>& st, const std::string& at, float height) {
    if (BeginCard("##checks", ImVec2(0, height))) {
        CardTitle("Состояние", at.empty() ? std::string() : "обновлено в " + at);
        ImGui::Dummy(ImVec2(0, S(2)));
        ImDrawList* d = ImGui::GetWindowDrawList();
        float rowH = S(31);
        float left = ImGui::GetCursorScreenPos().x;
        float right = ImGui::GetWindowPos().x + ImGui::GetWindowWidth() - S(20);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(ImGui::GetStyle().ItemSpacing.x, 0));  // строки вплотную
        if (!st) {
            for (int i = 0; i < 8; ++i) {  // скелетон
                ImVec2 p = ImGui::GetCursorScreenPos();
                float a = 0.55f + 0.25f * sinf((float)ImGui::GetTime() * 3.0f + i * 0.5f);
                ImU32 sk = RGBc(226, 231, 239, (int)(255 * a));
                d->AddCircleFilled(ImVec2(left + S(9), p.y + rowH * 0.5f), S(9), sk);
                d->AddRectFilled(ImVec2(left + S(28), p.y + rowH * 0.5f - S(6)), ImVec2(left + S(28) + S(170.0f + (i % 3) * 30.0f), p.y + rowH * 0.5f + S(6)), sk, S(6));
                d->AddRectFilled(ImVec2(right - S(120.0f - (i % 2) * 30.0f), p.y + rowH * 0.5f - S(6)), ImVec2(right, p.y + rowH * 0.5f + S(6)), sk, S(6));
                ImGui::Dummy(ImVec2(0, rowH));
            }
        } else {
            int i = 0;
            for (const CheckItem& it : st->items) {
                ImVec2 p = ImGui::GetCursorScreenPos();
                ImGui::PushID(i);
                ImGui::InvisibleButton("##row", ImVec2(right - left, rowH));
                bool hov = ImGui::IsItemHovered();
                ImGui::PopID();
                if (hov) d->AddRectFilled(ImVec2(left - S(8), p.y), ImVec2(right + S(8), p.y + rowH), RGBc(244, 247, 252), S(8));
                if (i > 0) d->AddLine(ImVec2(left, p.y), ImVec2(right, p.y), RGBc(238, 241, 246), S(1));
                DrawStatusIcon(d, ImVec2(left + S(9), p.y + rowH * 0.5f), S(9), it.level);
                d->AddText(fBody, fBody->FontSize, ImVec2(left + S(28), p.y + (rowH - fBody->FontSize) * 0.5f), cText, it.title.c_str());
                ImU32 vc = it.level == Level::Bad ? cBad : it.level == Level::Warn ? cWarn : cMuted;
                ImFont* vf = (it.level == Level::Bad || it.level == Level::Warn) ? fSemi : fBody;
                TextRight(d, vf, right, p.y + (rowH - vf->FontSize) * 0.5f, vc, it.value);
                if (hov && !it.hint.empty()) {
                    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(12), S(10)));
                    ImGui::BeginTooltip();
                    ImGui::PushTextWrapPos(S(380));
                    ImGui::TextUnformatted(it.hint.c_str());
                    ImGui::PopTextWrapPos();
                    ImGui::EndTooltip();
                    ImGui::PopStyleVar();
                }
                ++i;
            }
        }
        ImGui::PopStyleVar();
    }
    EndCard();
}

void DrawLog(const std::vector<LogLine>& log, const std::optional<FixResult>& fix, bool fixing, bool scrollToEnd) {
    if (BeginCard("##log", ImVec2(0, ImGui::GetContentRegionAvail().y))) {
        std::string right;
        if (fixing) right = "выполняется…";
        else if (fix) right = !fix->ok ? "ошибка" : fix->warnings ? "готово с предупреждениями" : "готово";
        CardTitle("Ход ремонта", right);

        if (!log.empty()) {  // кнопка копирования
            ImGui::SameLine();
            float bw = S(96);
            float x = ImGui::GetWindowWidth() - S(20) - bw - (right.empty() ? 0 : fSmall->CalcTextSizeA(fSmall->FontSize, FLT_MAX, 0, right.c_str()).x + S(14));
            ImGui::SetCursorPosX(x);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() - S(3));
            ImGui::PushFont(fSmall);
            ImGui::PushStyleColor(ImGuiCol_Button, V(cNeutral));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, V(RGBc(226, 232, 241)));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, V(RGBc(214, 222, 234)));
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(S(10), S(4)));
            if (ImGui::Button("Копировать", ImVec2(bw, 0))) {
                std::string all;
                for (const LogLine& l : log) {
                    all += l.step ? "\n== " : (l.level == Level::Ok ? "  [ok] " : l.level == Level::Warn ? "  [!!] " : l.level == Level::Bad ? "  [ОШИБКА] " : "       ");
                    all += l.text + "\n";
                }
                ImGui::SetClipboardText(all.c_str());
            }
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(3);
            ImGui::PopFont();
        }
        ImGui::Dummy(ImVec2(0, S(2)));

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
        ImGui::BeginChild("##logscroll", ImVec2(0, 0), ImGuiChildFlags_None);
        ImDrawList* d = ImGui::GetWindowDrawList();
        if (log.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, V(cMuted));
            ImGui::TextWrapped("Нажмите «Починить»: утилита остановит службу RDP, удалит повреждённые сертификаты, "
                               "выпустит новый через штатный провайдер Microsoft в обход КриптоПро, привяжет его к RDP и проверит результат.");
            ImGui::PopStyleColor();
        }
        for (size_t i = 0; i < log.size(); ++i) {
            const LogLine& l = log[i];
            if (l.step) {
                if (i > 0) ImGui::Dummy(ImVec2(0, S(2)));
                ImGui::PushFont(fSemi);
                ImGui::TextUnformatted(l.text.c_str());
                ImGui::PopFont();
                continue;
            }
            ImVec2 p = ImGui::GetCursorScreenPos();
            float lh = fBody->FontSize;
            if (l.level == Level::Info) {
                d->AddCircleFilled(ImVec2(p.x + S(7), p.y + lh * 0.55f), S(2.5f), cInfo);
            } else {
                DrawStatusIcon(d, ImVec2(p.x + S(7), p.y + lh * 0.55f), S(7), l.level);
            }
            ImGui::SetCursorScreenPos(ImVec2(p.x + S(22), p.y));
            ImGui::PushStyleColor(ImGuiCol_Text, V(l.level == Level::Bad ? cBad : l.level == Level::Info ? cMuted : cText));
            ImGui::PushTextWrapPos(0);
            ImGui::TextUnformatted(l.text.c_str());
            ImGui::PopTextWrapPos();
            ImGui::PopStyleColor();
        }
        if (fixing) {
            ImVec2 p = ImGui::GetCursorScreenPos();
            DrawSpinner(d, ImVec2(p.x + S(7), p.y + fBody->FontSize * 0.55f), S(6), cAccent, S(2));
            ImGui::Dummy(ImVec2(0, fBody->FontSize));
        }
        if (fix && !fixing) {
            ImGui::Dummy(ImVec2(0, S(4)));
            ImVec2 p = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            float h = S(40);
            Level lv = !fix->ok ? Level::Bad : fix->warnings ? Level::Warn : Level::Ok;
            ImU32 bg = lv == Level::Ok ? cOkSoft : lv == Level::Warn ? cWarnSoft : cBadSoft;
            d->AddRectFilled(p, ImVec2(p.x + w, p.y + h), bg, S(10));
            DrawStatusIcon(d, ImVec2(p.x + S(20), p.y + h * 0.5f), S(10), lv);
            std::string msg = !fix->ok ? "Ремонт прерван - см. ошибку выше"
                            : fix->warnings ? "Сертификат перевыпущен, но есть предупреждения"
                                            : "Сертификат перевыпущен и привязан, RDP отвечает";
            d->AddText(fSemi, fSemi->FontSize, ImVec2(p.x + S(40), p.y + (h - fSemi->FontSize) * 0.5f), cText, msg.c_str());
            ImGui::Dummy(ImVec2(w, h));
        }
        if (scrollToEnd) ImGui::SetScrollHereY(1.0f);
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
    EndCard();
}

void DrawUI() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##main", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                                    ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    std::optional<Status> st;
    std::vector<LogLine> log;
    std::optional<FixResult> fix;
    std::string at;
    bool scrollToEnd;
    {
        std::lock_guard<std::mutex> lk(g_app.mu);
        st = g_app.status; log = g_app.log; fix = g_app.fix; at = g_app.checkedAt;
        scrollToEnd = g_app.logScrollToEnd; g_app.logScrollToEnd = false;
    }
    bool checking = g_app.checking, fixing = g_app.fixing;

    DrawHeader();
    ImGui::Dummy(ImVec2(0, S(4)));
    DrawBanner(st, checking, fixing);
    ImGui::Dummy(ImVec2(0, S(2)));

    int rows = st ? (int)st->items.size() : 8;
    DrawChecks(st, at, S(16) * 2 + fSemi->FontSize + ImGui::GetStyle().ItemSpacing.y * 2 + S(2) + rows * S(31) + S(2));
    ImGui::Dummy(ImVec2(0, S(2)));

    // Кнопки.
    float bh = S(46);
    bool busy = checking || fixing;
    std::string fixLabel = fixing ? "Чиним…" : "Починить";
    if (Button("fix", fixLabel, ImVec2(S(220), bh), BtnKind::Primary, !busy, fixing)) StartFix();
    ImGui::SameLine(0, S(12));
    if (Button("recheck", checking && !fixing ? "Проверяем…" : "Проверить снова", ImVec2(S(190), bh), BtnKind::Secondary, !busy, checking && !fixing))
        StartChecks();
    if (st && st->verdict == Verdict::Working && !fixing) {
        ImGui::SameLine(0, S(16));
        ImVec2 p = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddText(fSmall, fSmall->FontSize, ImVec2(p.x, p.y + (bh - fSmall->FontSize * 2 - S(2)) * 0.5f), cMuted,
                                            "Всё работает. «Починить» можно нажать\nи сейчас - сертификат будет перевыпущен.");
        ImGui::Dummy(ImVec2(0, bh));
    }
    ImGui::Dummy(ImVec2(0, S(2)));

    DrawLog(log, fix, fixing, scrollToEnd);
    ImGui::End();
}

// ---------- окно ----------

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp)) return 1;
    switch (msg) {
    case WM_SIZE:
        if (wp != SIZE_MINIMIZED) { g_resizeW = LOWORD(lp); g_resizeH = HIWORD(lp); }
        return 0;
    case WM_DPICHANGED: {
        g_scale = HIWORD(wp) / 96.0f;
        g_dpiChanged = true;
        const RECT* r = (const RECT*)lp;
        SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_GETMINMAXINFO: {
        auto* mm = (MINMAXINFO*)lp;
        mm->ptMinTrackSize = { (LONG)(640 * g_scale), (LONG)(620 * g_scale) };
        return 0;
    }
    case WM_CLOSE:
        if (g_app.fixing) {  // не даём закрыть окно посреди ремонта
            MessageBeep(MB_ICONWARNING);
            return 0;
        }
        break;
    case WM_SYSCOMMAND:
        if ((wp & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ---------- режим без окна ----------

int RunHeadless(bool fix) {
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    std::wstring path = std::wstring(tmp) + L"rdp-cert-fix.log";
    FILE* f = nullptr;
    _wfopen_s(&f, path.c_str(), L"wb");
    auto out = [&](const std::string& s) { if (f) { fwrite(s.data(), 1, s.size(), f); fflush(f); } };
    out("\xEF\xBB\xBFRDP Cert Fix v" APP_VERSION "\r\n");
    int rc = 0;
    if (fix) {
        FixResult r = RunFix([&](const LogLine& l) {
            out(l.step ? "\r\n== " + l.text + "\r\n"
                       : std::string(l.level == Level::Ok ? "  [ok] " : l.level == Level::Warn ? "  [!!] " : l.level == Level::Bad ? "  [ОШИБКА] " : "       ") + l.text + "\r\n");
        });
        rc = !r.ok ? 1 : r.warnings ? 2 : 0;
    }
    Status st = RunChecks();
    out("\r\n== Состояние: " + st.summary + "\r\n");
    for (const CheckItem& it : st.items)
        out(std::string(it.level == Level::Ok ? "  [ok] " : it.level == Level::Warn ? "  [!!] " : it.level == Level::Bad ? "  [xx] " : "  [--] ") + it.title + ": " + it.value + "\r\n");
    if (!fix) rc = st.verdict == Verdict::Working ? 0 : st.verdict == Verdict::CertBroken ? 3 : 4;
    if (f) fclose(f);
    return rc;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int i = 1; i < argc; ++i) {
        const wchar_t* a = argv[i];
        if (*a == L'/' || *a == L'-') ++a;
        if (!_wcsicmp(a, L"fix") || !_wcsicmp(a, L"quiet")) return RunHeadless(true);
        if (!_wcsicmp(a, L"check")) return RunHeadless(false);
    }
    LocalFree(argv);

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    ImGui_ImplWin32_EnableDpiAwareness();
    g_scale = ImGui_ImplWin32_GetDpiScaleForMonitor(MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_APP));
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"RdpCertFixWnd";
    RegisterClassExW(&wc);

    // Размер окна по логическим пикселям, но не больше рабочей области.
    RECT work; SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    RECT r{ 0, 0, (LONG)(780 * g_scale), (LONG)(840 * g_scale) };
    DWORD style = WS_OVERLAPPEDWINDOW;
    AdjustWindowRectEx(&r, style, FALSE, 0);
    int ww = std::min<int>(r.right - r.left, work.right - work.left);
    int wh = std::min<int>(r.bottom - r.top, (int)((work.bottom - work.top) * 0.95));
    int wx = work.left + ((work.right - work.left) - ww) / 2;
    int wy = work.top + ((work.bottom - work.top) - wh) / 2;
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"RDP Cert Fix", style, wx, wy, ww, wh, nullptr, nullptr, hInst, nullptr);

    // Светлая строка заголовка в цвет фона (Windows 11).
    COLORREF cap = RGB(244, 246, 250);
    DwmSetWindowAttribute(hwnd, 35 /* DWMWA_CAPTION_COLOR */, &cap, sizeof(cap));

    if (!CreateDevice(hwnd)) {
        MessageBoxW(hwnd, L"Не удалось инициализировать Direct3D 11.\nЗапустите с ключом /fix для ремонта без окна.", L"RDP Cert Fix", MB_ICONERROR);
        return 1;
    }
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    BuildFonts(g_scale);
    ApplyStyle(g_scale);
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_dev, g_ctx);

    int iw = 0, ih = 0;
    g_icon = LoadPngResource(IDR_ICON_PNG, iw, ih);

    if (!IsProcessElevated()) {
        std::lock_guard<std::mutex> lk(g_app.mu);
        g_app.log.push_back({ Level::Bad, "Программа запущена без прав администратора - проверка неполная, ремонт невозможен.", false });
    }
    StartChecks();

    bool done = false;
    while (!done) {
        // В простое не крутим кадры впустую.
        bool animate = g_app.checking || g_app.fixing || !g_app.status;
        if (!animate) MsgWaitForMultipleObjects(0, nullptr, FALSE, 250, QS_ALLINPUT);
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;
        if (IsIconic(hwnd)) { Sleep(50); continue; }

        if (g_resizeW) {
            DestroyRT();
            g_swap->ResizeBuffers(0, g_resizeW, g_resizeH, DXGI_FORMAT_UNKNOWN, 0);
            g_resizeW = g_resizeH = 0;
            CreateRT();
        }
        if (g_dpiChanged) {
            g_dpiChanged = false;
            BuildFonts(g_scale);
            ApplyStyle(g_scale);
            ImGui_ImplDX11_InvalidateDeviceObjects();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        DrawUI();
        ImGui::Render();

        const float clear[4] = { 244 / 255.f, 246 / 255.f, 250 / 255.f, 1 };
        g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_ctx->ClearRenderTargetView(g_rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swap->Present(1, 0);
    }

    // Не рвём ремонт на середине: ждём фоновые потоки.
    while (g_app.fixing || g_app.checking) Sleep(50);

    if (g_icon) g_icon->Release();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    DestroyDevice();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, hInst);
    return 0;
}
