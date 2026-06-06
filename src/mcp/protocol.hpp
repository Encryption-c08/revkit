#pragma once

#include <string>
#include <optional>
#include <nlohmann/json.hpp>

namespace revkit::mcp
{

using json = nlohmann::json;

constexpr int ERR_PARSE     = -32700;
constexpr int ERR_INVALID   = -32600;
constexpr int ERR_NOT_FOUND = -32601;
constexpr int ERR_PARAMS    = -32602;
constexpr int ERR_INTERNAL  = -32603;

struct Request
{
    json        id;
    std::string method;
    json        params;

    static std::optional<Request> parse(const json& j)
    {
        if (!j.contains("method") || !j["method"].is_string())
            return std::nullopt;
        Request r;
        r.method = j["method"].get<std::string>();
        r.id     = j.contains("id") ? j["id"] : json(nullptr);
        r.params = j.contains("params") ? j["params"] : json(nullptr);
        return r;
    }
};

inline json make_result(const json& id, const json& result)
{
    return json{
        {"jsonrpc", "2.0"},
        {"id",      id},
        {"result",  result}
    };
}

inline json make_error(const json& id, int code, const std::string& msg)
{
    return json{
        {"jsonrpc", "2.0"},
        {"id",      id},
        {"error",   {{"code", code}, {"message", msg}}}
    };
}

inline json tool_ok(const std::string& text)
{
    return json{
        {"content", json::array({{{"type", "text"}, {"text", text}}})},
        {"isError", false}
    };
}

inline json tool_ok(const json& data)
{
    return tool_ok(data.dump(2));
}

inline json tool_err(const std::string& text)
{
    return json{
        {"content", json::array({{{"type", "text"}, {"text", text}}})},
        {"isError", true}
    };
}

}
