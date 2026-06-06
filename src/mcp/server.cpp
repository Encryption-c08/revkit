#include "server.hpp"
#include "tools/process_tools.hpp"
#include "tools/memory_tools.hpp"
#include "tools/analysis_tools.hpp"
#include "tools/game_tools.hpp"

namespace revkit::mcp
{

Server::Server()
{
    register_tool(tools::schema_process_list(),    tools::handle_process_list);
    register_tool(tools::schema_process_attach(),  tools::handle_process_attach);
    register_tool(tools::schema_process_detach(),  tools::handle_process_detach);
    register_tool(tools::schema_process_status(),  tools::handle_process_status);
    register_tool(tools::schema_module_list(),     tools::handle_module_list);
    register_tool(tools::schema_module_find(),     tools::handle_module_find);

    register_tool(tools::schema_memory_read(),     tools::handle_memory_read);
    register_tool(tools::schema_memory_write(),          tools::handle_memory_write);
    register_tool(tools::schema_memory_write_physical(), tools::handle_memory_write_physical);
    register_tool(tools::schema_memory_query(),    tools::handle_memory_query);
    register_tool(tools::schema_memory_regions(),  tools::handle_memory_regions);
    register_tool(tools::schema_memory_scan(),     tools::handle_memory_scan);
    register_tool(tools::schema_pointer_chain(),   tools::handle_pointer_chain);

    register_tool(tools::schema_pe_info(),         tools::handle_pe_info);
    register_tool(tools::schema_pe_exports(),      tools::handle_pe_exports);
    register_tool(tools::schema_pe_imports(),      tools::handle_pe_imports);
    register_tool(tools::schema_pe_sections(),     tools::handle_pe_sections);
    register_tool(tools::schema_string_scan(),     tools::handle_string_scan);

    register_tool(tools::schema_disassemble(),      tools::handle_disassemble);
    register_tool(tools::schema_value_scan(),       tools::handle_value_scan);
    register_tool(tools::schema_xref_scan(),        tools::handle_xref_scan);
    register_tool(tools::schema_module_info_full(), tools::handle_module_info_full);

}

void Server::register_tool(json schema, Handler h)
{
    std::string name = schema["name"].get<std::string>();
    m_tools[name] = ToolEntry{ std::move(schema), std::move(h) };
}

json Server::handle_request(const json& j)
{
    try
    {
        auto req = Request::parse(j);
        if (!req.has_value())
            return make_error(nullptr, ERR_INVALID, "invalid JSON-RPC request");
        json resp = dispatch(req.value());
        return resp.is_null() ? json::object() : resp;
    }
    catch (const std::exception& e)
    {
        return make_error(nullptr, ERR_INTERNAL, e.what());
    }
}

json Server::dispatch(const Request& req)
{
    if (req.method == "initialize")
        return make_result(req.id, on_initialize(req.params));
    if (req.method == "notifications/initialized")
        return nullptr;
    if (req.method == "ping")
        return make_result(req.id, json::object());
    if (req.method == "tools/list")
        return make_result(req.id, on_tools_list(req.params));
    if (req.method == "tools/call")
        return make_result(req.id, on_tools_call(req.params));
    return make_error(req.id, ERR_NOT_FOUND, "method not found: " + req.method);
}

json Server::on_initialize(const json&)
{
    return {
        { "protocolVersion", "2024-11-05" },
        { "capabilities",    { { "tools", json::object() } } },
        { "serverInfo",      { { "name", "revkit" }, { "version", "1.0.0" } } },
        { "instructions",    "Live process memory RE. Use process_attach first, "
                             "then memory/pe/string tools. Pairs with IDA MCP." }
    };
}

json Server::on_tools_list(const json&)
{
    json tools = json::array();
    for (auto& [name, entry] : m_tools)
        tools.push_back(entry.schema);
    return { { "tools", tools } };
}

json Server::on_tools_call(const json& params)
{
    if (!params.contains("name") || !params["name"].is_string())
        return tool_err("missing tool name");

    std::string name = params["name"].get<std::string>();
    auto it = m_tools.find(name);
    if (it == m_tools.end())
        return tool_err("unknown tool: " + name);

    json args = json::object();
    if (params.contains("arguments") && params["arguments"].is_object())
        args = params["arguments"];

    return it->second.handler(args);
}

}
