#pragma once

#include <functional>
#include <string>
#include <unordered_map>
#include "protocol.hpp"

namespace revkit::mcp
{

using Handler = std::function<json(const json&)>;

struct ToolEntry
{
    json    schema;
    Handler handler;
};

class Server
{
public:
    Server();
    void register_tool(json schema, Handler h);

    json handle_request(const json& j);

private:
    json dispatch(const Request& req);
    json on_initialize(const json& params);
    json on_tools_list(const json& params);
    json on_tools_call(const json& params);

    std::unordered_map<std::string, ToolEntry> m_tools;
};

}
