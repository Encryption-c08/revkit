#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <functional>
#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>

namespace revkit::net
{

using json = nlohmann::json;

class HttpServer
{
public:
    using Handler = std::function<json(const json& body, const std::string& peer_ip)>;
    using LogFn   = std::function<void(const std::string& level, const std::string& msg)>;

    HttpServer(uint16_t port, Handler handler, LogFn log_fn)
        : m_port(port)
        , m_handler(std::move(handler))
        , m_log(std::move(log_fn))
    {}

    ~HttpServer()
    {
        if (m_sock != INVALID_SOCKET) closesocket(m_sock);
        WSACleanup();
    }

    bool start()
    {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        {
            m_log("err", "WSAStartup failed");
            return false;
        }

        m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_sock == INVALID_SOCKET)
        {
            m_log("err", "socket() failed: " + std::to_string(WSAGetLastError()));
            return false;
        }

        int opt = 1;
        setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = htons(m_port);

        if (bind(m_sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
        {
            m_log("err", "bind() failed on port " + std::to_string(m_port)
                       + " (already in use?)");
            return false;
        }

        if (listen(m_sock, SOMAXCONN) == SOCKET_ERROR)
        {
            m_log("err", "listen() failed");
            return false;
        }

        return true;
    }

    void run()
    {
        while (true)
        {
            sockaddr_in peer_addr{};
            int peer_len = sizeof(peer_addr);
            SOCKET client = accept(m_sock, (sockaddr*)&peer_addr, &peer_len);
            if (client == INVALID_SOCKET) continue;

            char peer_ip[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));

            try
            {
                handle_client(client, std::string(peer_ip));
            }
            catch (const std::exception& e)
            {
                m_log("err", std::string("connection error: ") + e.what());
            }
            catch (...)
            {
                m_log("err", "unknown connection error");
            }

            closesocket(client);
        }
    }

private:
    void handle_client(SOCKET sock, const std::string& peer_ip)
    {
        std::string buf;
        buf.reserve(4096);
        char tmp[2048];
        size_t hdr_end = std::string::npos;

        while (hdr_end == std::string::npos)
        {
            int n = recv(sock, tmp, sizeof(tmp), 0);
            if (n <= 0) return;
            buf.append(tmp, n);
            hdr_end = buf.find("\r\n\r\n");
        }

        std::string headers   = buf.substr(0, hdr_end);
        std::string body      = buf.substr(hdr_end + 4);

        std::string http_method, path;
        {
            std::istringstream ss(headers);
            ss >> http_method >> path;
        }

        int content_len = 0;
        {
            std::string lower = headers;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            auto pos = lower.find("content-length:");
            if (pos != std::string::npos)
            {
                pos += 15;
                while (pos < lower.size() && lower[pos] == ' ') ++pos;
                try { content_len = std::stoi(lower.substr(pos)); } catch (...) {}
            }
        }

        while ((int)body.size() < content_len)
        {
            int n = recv(sock, tmp, (int)std::min((int)sizeof(tmp),
                                                  content_len - (int)body.size()), 0);
            if (n <= 0) break;
            body.append(tmp, n);
        }

        std::string resp_body;
        if (http_method == "GET" && path == "/health")
        {
            resp_body = R"({"status":"ok"})";
        }
        else if (http_method == "POST")
        {
            try
            {
                json req_json = json::parse(body);
                json result   = m_handler(req_json, peer_ip);
                resp_body     = result.dump();
            }
            catch (const std::exception& e)
            {
                resp_body = json{
                    {"jsonrpc","2.0"},{"id",nullptr},
                    {"error",{{"code",-32700},{"message",std::string(e.what())}}}
                }.dump();
            }
        }
        else
        {
            resp_body = R"({"error":"not found"})";
        }

        std::ostringstream http_resp;
        http_resp << "HTTP/1.1 200 OK\r\n"
                  << "Content-Type: application/json\r\n"
                  << "Content-Length: " << resp_body.size() << "\r\n"
                  << "Connection: close\r\n"
                  << "\r\n"
                  << resp_body;
        std::string out = http_resp.str();
        send(sock, out.c_str(), (int)out.size(), 0);
    }

    uint16_t m_port;
    Handler  m_handler;
    LogFn    m_log;
    SOCKET   m_sock = INVALID_SOCKET;
};

}
