#include "mcp/http_server.hpp"
#include "util/privilege.hpp"
#include "util/hvci.hpp"
#include "core/memory.hpp"
#include "core/process.hpp"
#include "mcp/server.hpp"
#include "driver/backend.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <wrl.h>
#include "WebView2.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <thread>
#include <chrono>
#include <sstream>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

using Microsoft::WRL::Callback;

static constexpr uint16_t DEFAULT_PORT = 13338;

static std::atomic<bool>     g_driver_ok{ false };
static std::atomic<bool>     g_priv_ok{ false };
static std::atomic<uint16_t> g_port{ DEFAULT_PORT };
static std::atomic<uint32_t> g_attached_pid{ 0 };
static char                  g_target_name[64] = "-";
static char                  g_backend_str[32] = "-";
static std::mutex            g_names_mutex;
static std::atomic<bool>     g_verbose{ false };

static HWND                     g_hwnd       = nullptr;
static ICoreWebView2*           g_webview    = nullptr;
static ICoreWebView2Controller* g_controller = nullptr;

static std::mutex               g_post_mutex;
static std::vector<std::string> g_post_queue;
static std::atomic<bool>        g_page_ready{ false };

#define WM_WEBPOST (WM_APP + 10)
#define WM_NAVDONE (WM_APP + 11)

static std::atomic<int>  g_reads_this_sec{ 0 };
static std::atomic<int>  g_writes_this_sec{ 0 };

struct ActivitySample { int reads; int writes; };
static std::deque<ActivitySample> g_activity;
static std::mutex                 g_activity_mutex;

static void push_log(const std::string& level, const std::string& msg, const std::string& detail = "");

static std::string exe_dir()
{
    char buf[MAX_PATH]{};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string p(buf);
    auto s = p.find_last_of("\\/");
    return (s != std::string::npos) ? p.substr(0, s + 1) : ".\\";
}

static bool driver_is_loaded()
{
    HANDLE h = CreateFileA("\\\\.\\RvKit",
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

static bool driver_unload()
{
    HANDLE h = CreateFileA("\\\\.\\RvKit",
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD code = CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS);
    DWORD ret  = 0;
    DeviceIoControl(h, code, nullptr, 0, nullptr, 0, &ret, nullptr);
    CloseHandle(h);
    Sleep(200);
    return !driver_is_loaded();
}

static bool try_kdmapper(const std::string&)
{
    std::string dir    = exe_dir();
    std::string driver = dir + "revkit-driver.sys";
    std::string mapper = dir + "kdmapper.exe";

    HANDLE h = CreateFileA("\\\\.\\RvKit",
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }

    if (GetFileAttributesA(driver.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        push_log("err", "revkit-driver.sys not found in exe directory");
        return false;
    }

    if (GetFileAttributesA(mapper.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        push_log("err", "kdmapper.exe not found in exe directory");
        return false;
    }

    std::string cmd = "\"" + mapper + "\" \"" + driver + "\"";

    STARTUPINFOA si{};
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()),
                        nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        push_log("err", "failed to launch kdmapper.exe — run as administrator");
        return false;
    }

    WaitForSingleObject(pi.hProcess, 15000);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exit_code != 0)
    {
        push_log("err", "kdmapper.exe exited with code " + std::to_string(exit_code) + " — run as administrator");
        return false;
    }

    for (int i = 0; i < 20; i++)
    {
        Sleep(100);
        h = CreateFileA("\\\\.\\RvKit",
            GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
    }

    push_log("err", "driver mapped but device not found — check test signing mode");
    return false;
}

static std::string js_escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s)
    {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else                out += (char)c;
    }
    return out;
}

static void webview_post(const std::string& json)
{
    if (!g_hwnd) return;
    {
        std::lock_guard<std::mutex> lk(g_post_mutex);
        g_post_queue.push_back(json);
    }
    PostMessageA(g_hwnd, WM_WEBPOST, 0, 0);
}

static void push_log(const std::string& level, const std::string& msg,
                     const std::string& detail)
{
    SYSTEMTIME t{};
    GetLocalTime(&t);
    char ts[12];
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d", t.wHour, t.wMinute, t.wSecond);

    std::string d_esc = js_escape(detail.empty() ? msg : detail);
    std::string m_esc = js_escape(msg);

    char buf[2048];
    snprintf(buf, sizeof(buf),
        R"({"type":"log","level":"%s","time":"%s","msg":"%s","detail":"%s"})",
        level.c_str(), ts, m_esc.c_str(), d_esc.c_str());
    webview_post(buf);
}

static void push_status()
{
    char bk[32], tgt[64];
    {
        std::lock_guard<std::mutex> lk(g_names_mutex);
        snprintf(bk,  sizeof(bk),  "%s", g_backend_str);
        snprintf(tgt, sizeof(tgt), "%s", g_target_name);
    }
    char buf[512];
    snprintf(buf, sizeof(buf),
        R"({"type":"status","driver":%s,"priv":%s,"port":%u,"pid":%u,"target":"%s","backend":"%s"})",
        g_driver_ok.load() ? "true" : "false",
        g_priv_ok.load()   ? "true" : "false",
        (unsigned)g_port.load(),
        (unsigned)g_attached_pid.load(),
        js_escape(tgt).c_str(),
        js_escape(bk).c_str());
    webview_post(buf);
}

static void push_activity()
{
    std::string arr = "[";
    {
        std::lock_guard<std::mutex> lk(g_activity_mutex);
        for (size_t i = 0; i < g_activity.size(); i++)
        {
            if (i) arr += ",";
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "[%d,%d]", g_activity[i].reads, g_activity[i].writes);
            arr += tmp;
        }
    }
    arr += "]";
    std::string json = R"({"type":"activity","data":)" + arr + "}";
    webview_post(json);
}

static DWORD WINAPI activity_thread(LPVOID)
{
    while (true)
    {
        Sleep(1000);
        int r = g_reads_this_sec.exchange(0);
        int w = g_writes_this_sec.exchange(0);
        {
            std::lock_guard<std::mutex> lk(g_activity_mutex);
            g_activity.push_back({r, w});
            while ((int)g_activity.size() > 30)
                g_activity.pop_front();
        }
        push_activity();
        push_status();
    }
    return 0;
}

static void handle_cmd(const std::string& line)
{
    if (line.empty()) return;
    if (line[0] != '/') return;

    std::vector<std::string> tokens;
    std::string tok;
    for (char c : line)
    {
        if (c == ' ') { if (!tok.empty()) { tokens.push_back(tok); tok.clear(); } }
        else tok += c;
    }
    if (!tok.empty()) tokens.push_back(tok);
    if (tokens.empty()) return;

    std::string cmd = tokens[0];

    if (cmd == "/help")
    {
        push_log("info", "commands: /load /unload /status /verbose");
    }
    else if (cmd == "/verbose")
    {
        bool v = !g_verbose.load();
        g_verbose.store(v);
        push_log("info", std::string("verbose: ") + (v ? "on" : "off"));
    }
    else if (cmd == "/status")
    {
        bool drv = driver_is_loaded();
        push_log(drv ? "ok" : "warn", drv ? "driver: kernel mode" : "driver: not loaded");
        uint32_t pid = g_attached_pid.load();
        if (pid) push_log("ok",   "attached pid=" + std::to_string(pid));
        else     push_log("info", "not attached");
    }
    else if (cmd == "/load")
    {
        push_log("info", "loading kernel driver...");
        if (driver_is_loaded())
        {
            push_log("ok", "already loaded");
        }
        else if (try_kdmapper(""))
        {
            revkit::core::Memory::get().try_use_driver();
            g_driver_ok.store(true);
            push_log("ok", "kernel driver loaded");
        }
        else
        {
            push_log("err", "failed â€” run as admin");
        }
        push_status();
    }
    else if (cmd == "/unload")
    {
        push_log("info", "unloading driver...");
        if (!driver_is_loaded())
        {
            push_log("warn", "not loaded");
        }
        else if (driver_unload())
        {
            g_driver_ok.store(false);
            push_log("ok", "driver unloaded");
        }
        else
        {
            push_log("err", "unload failed");
        }
        push_status();
    }
    else
    {
        push_log("warn", "unknown command â€” /help for list");
    }
}

static std::string req_summary(const nlohmann::json& j)
{
    std::string method = j.value("method", "?");
    if (method == "tools/call" && j.contains("params"))
    {
        auto& p = j["params"];
        std::string name = p.value("name", "?");
        std::string args = p.contains("arguments") ? p["arguments"].dump() : "{}";
        if (args.size() > 60) args = args.substr(0, 57) + "...";
        return name + "  " + args;
    }
    return method;
}

static std::string resp_summary(const nlohmann::json& resp)
{
    if (resp.contains("error"))
        return "err  " + resp["error"].value("message", "?");
    if (!resp.contains("result")) return "?";
    auto& r = resp["result"];
    if (r.contains("tools"))
        return std::to_string(r["tools"].size()) + " tools";
    if (r.contains("isError"))
    {
        bool is_err = r["isError"].get<bool>();
        std::string text;
        if (r.contains("content") && !r["content"].empty())
            text = r["content"][0].value("text", "");
        if (text.size() > 60) text = text.substr(0, 57) + "...";
        return is_err ? ("err  " + text) : ("ok  " + text);
    }
    std::string s = r.dump();
    if (s.size() > 60) s = s.substr(0, 57) + "...";
    return s;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_SIZE:
        if (g_controller)
        {
            RECT rc{};
            GetClientRect(hwnd, &rc);
            g_controller->put_Bounds(rc);
        }
        return 0;

    case WM_WEBPOST:
    case WM_NAVDONE:
    {
        if (!g_webview || !g_page_ready.load()) return 0;
        std::vector<std::string> batch;
        {
            std::lock_guard<std::mutex> lk(g_post_mutex);
            batch.swap(g_post_queue);
        }
        for (const auto& json : batch)
        {
            std::wstring ws(json.begin(), json.end());
            g_webview->PostWebMessageAsString(ws.c_str());
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR lpCmdLine, int)
{
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    uint16_t port = DEFAULT_PORT;
    {
        int argc;
        wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        for (int i = 1; i < argc; i++)
        {
            if (wcscmp(argv[i], L"--port") == 0 && i + 1 < argc)
            {
                int p = _wtoi(argv[++i]);
                if (p > 0 && p < 65536) port = static_cast<uint16_t>(p);
            }
        }
        if (argv) LocalFree(argv);
    }
    g_port.store(port);

    WNDCLASSEXA wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(10, 10, 15));
    wc.lpszClassName = "revkit_wnd";
    RegisterClassExA(&wc);

    g_hwnd = CreateWindowExA(
        0, "revkit_wnd", "revkit | kernel memory RE",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1140, 700,
        nullptr, nullptr, hInst, nullptr);

    if (!g_hwnd) return 1;

    {
        BOOL dark = TRUE;
        DwmSetWindowAttribute(g_hwnd, 20, &dark, sizeof(dark));
        DwmSetWindowAttribute(g_hwnd, 19, &dark, sizeof(dark));
        COLORREF bg = RGB(10, 10, 15);
        DwmSetWindowAttribute(g_hwnd, 35, &bg, sizeof(bg));
    }

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    bool priv_ok = revkit::util::enable_debug_privilege();
    bool drv_ok  = revkit::core::Memory::get().try_use_driver();
    g_priv_ok.store(priv_ok);
    g_driver_ok.store(drv_ok);
    {
        std::lock_guard<std::mutex> lk(g_names_mutex);
        snprintf(g_backend_str, sizeof(g_backend_str), drv_ok ? "kernel" : "RPM");
    }

    if (!drv_ok)
    {
        if (try_kdmapper(""))
            drv_ok = revkit::core::Memory::get().try_use_driver();
    }

    if (!drv_ok && (revkit::util::hvci_is_enabled() || revkit::util::blocklist_is_enabled()))
    {
        if (revkit::util::disable_hvci_and_blocklist())
        {
            Sleep(5000);
            revkit::util::reboot_now();
        }
    }

    if (!drv_ok)
    {
        if (try_kdmapper(""))
        {
            drv_ok = revkit::core::Memory::get().try_use_driver();
            g_driver_ok.store(drv_ok);
            std::lock_guard<std::mutex> lk(g_names_mutex);
            snprintf(g_backend_str, sizeof(g_backend_str), drv_ok ? "kernel" : "RPM");
        }
    }

    g_driver_ok.store(drv_ok);

    revkit::mcp::Server mcp_server;

    auto http_ptr = std::make_shared<revkit::net::HttpServer>(
        port,

        [&](const nlohmann::json& body, const std::string& peer) -> nlohmann::json
        {
            if (!revkit::core::Memory::get().using_driver())
            {
                if (revkit::core::Memory::get().try_use_driver())
                {
                    g_driver_ok.store(true);
                    std::lock_guard<std::mutex> lk(g_names_mutex);
                    snprintf(g_backend_str, sizeof(g_backend_str), "kernel");
                }
            }

            if (body.contains("params") && body["params"].contains("name"))
            {
                std::string name = body["params"]["name"].get<std::string>();
                if (name == "process_attach" && body["params"].contains("arguments"))
                {
                    auto& args = body["params"]["arguments"];
                    if (args.contains("pid") && args["pid"].is_number())
                        g_attached_pid.store(args["pid"].get<uint32_t>());
                    if (args.contains("name") && args["name"].is_string())
                    {
                        std::lock_guard<std::mutex> lk(g_names_mutex);
                        snprintf(g_target_name, sizeof(g_target_name), "%s",
                                 args["name"].get<std::string>().c_str());
                    }
                }
                if (name == "process_detach")
                {
                    g_attached_pid.store(0);
                    std::lock_guard<std::mutex> lk(g_names_mutex);
                    strcpy_s(g_target_name, "-");
                }
                if (name == "memory_read")  g_reads_this_sec.fetch_add(1);
                if (name == "memory_write") g_writes_this_sec.fetch_add(1);
            }

            try
            {
                std::string req_msg  = peer + "  " + req_summary(body);
                nlohmann::json resp  = mcp_server.handle_request(body);
                std::string rsp_msg  = resp_summary(resp);
                std::string method   = body.value("method", "");
                if (g_verbose.load() || method == "tools/call")
                {
                    std::string detail = "request:  " + body.dump(2) + "\nresponse: " + resp.dump(2);
                    push_log("req",  req_msg, detail);
                    push_log("resp", rsp_msg);
                }
                return resp;
            }
            catch (const std::exception& e)
            {
                push_log("err", std::string("handler: ") + e.what());
                return nlohmann::json{
                    {"jsonrpc","2.0"},{"id",nullptr},
                    {"error",{{"code",-32603},{"message",std::string(e.what())}}}
                };
            }
        },

        [](const std::string& level, const std::string& msg)
        {
            push_log(level, msg);
        }
    );

    if (!http_ptr->start())
        push_log("err", "failed to start http server on port " + std::to_string(port));
    else
    {
        push_log("ok", "listening  http://127.0.0.1:" + std::to_string(port));
        std::thread([http_ptr]()
        {
            try { http_ptr->run(); }
            catch (const std::exception& e) { push_log("err", std::string("http: ") + e.what()); }
        }).detach();
    }

    CreateThread(nullptr, 0, activity_thread, nullptr, 0, nullptr);

    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(nullptr, nullptr, nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [](HRESULT hrEnv, ICoreWebView2Environment* env) -> HRESULT
            {
                if (FAILED(hrEnv) || !env)
                {
                    MessageBoxA(g_hwnd, "WebView2 environment failed. Is Microsoft Edge installed?",
                                "revkit", MB_OK | MB_ICONERROR);
                    PostMessageA(g_hwnd, WM_DESTROY, 0, 0);
                    return S_OK;
                }
                env->CreateCoreWebView2Controller(g_hwnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [](HRESULT hrCtrl, ICoreWebView2Controller* ctrl) -> HRESULT
                        {
                            if (FAILED(hrCtrl) || !ctrl)
                            {
                                MessageBoxA(g_hwnd, "WebView2 controller failed to create.",
                                            "revkit", MB_OK | MB_ICONERROR);
                                PostMessageA(g_hwnd, WM_DESTROY, 0, 0);
                                return S_OK;
                            }

                            ctrl->AddRef();
                            g_controller = ctrl;

                            ICoreWebView2* wv = nullptr;
                            ctrl->get_CoreWebView2(&wv);
                            if (!wv)
                            {
                                PostMessageA(g_hwnd, WM_DESTROY, 0, 0);
                                return S_OK;
                            }
                            wv->AddRef();
                            g_webview = wv;

                            ICoreWebView2Settings* settings = nullptr;
                            wv->get_Settings(&settings);
                            if (settings)
                            {
                                settings->put_IsScriptEnabled(TRUE);
                                settings->put_AreDefaultContextMenusEnabled(FALSE);
                                settings->put_AreDevToolsEnabled(FALSE);
                                settings->put_IsStatusBarEnabled(FALSE);
                                settings->Release();
                            }

                            RECT rc{};
                            GetClientRect(g_hwnd, &rc);
                            ctrl->put_Bounds(rc);

                            std::string ui_path = exe_dir() + "app.html";
                            std::string url = "file:///";
                            for (char c : ui_path) url += (c == '\\') ? '/' : c;
                            std::wstring wurl(url.begin(), url.end());
                            wv->Navigate(wurl.c_str());

                            wv->add_NavigationCompleted(
                                Callback<ICoreWebView2NavigationCompletedEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2NavigationCompletedEventArgs*) -> HRESULT
                                    {
                                        g_page_ready.store(true);
                                        PostMessageA(g_hwnd, WM_NAVDONE, 0, 0);
                                        return S_OK;
                                    }).Get(), nullptr);

                            wv->add_WebMessageReceived(
                                Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT
                                    {
                                        LPWSTR raw = nullptr;
                                        args->TryGetWebMessageAsString(&raw);
                                        if (!raw) return S_OK;
                                        std::wstring ws(raw);
                                        CoTaskMemFree(raw);
                                        std::string s(ws.begin(), ws.end());
                                        try
                                        {
                                            auto j = nlohmann::json::parse(s);
                                            std::string t = j.value("type", "");
                                            if (t == "cmd")
                                            {
                                                std::string cmd = j.value("cmd", "");
                                                std::thread([cmd]{ handle_cmd(cmd); }).detach();
                                            }
                                        }
                                        catch (...) {}
                                        return S_OK;
                                    }).Get(), nullptr);

                            push_status();
                            push_log("ok", "revkit ready");
                            return S_OK;
                        }).Get());
                return S_OK;
            }).Get());

    if (FAILED(hr))
    {
        MessageBoxA(nullptr, "Failed to start WebView2. Make sure Microsoft Edge is installed.",
                    "revkit", MB_OK | MB_ICONERROR);
        return 1;
    }

    MSG msg{};
    while (GetMessageA(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return 0;
}
