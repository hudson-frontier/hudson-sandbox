# Optional local MCP adapter

This unpublished, optional package offers project-authenticated sandbox tools to a local MCP client that launches a stdio subprocess. HTTP and its existing Python SDK remain the lifecycle boundary. Installing an ordinary SDK or CLI does not install MCP. See [the adapter contract](../../docs/mcp-adapter.md) for schemas, bounds and recovery behavior.

From the repository root on Unix or WSL:

```sh
make mcp-setup
.venv-mcp/bin/python -m pip install --no-deps --no-build-isolation ./sdk/python ./sdk/mcp
.venv-mcp/bin/hudsonbox-mcp --config /absolute/private/client.json
```

Configure the MCP client to launch that absolute executable with the two arguments `--config` and the trusted configuration path. Configuration and credentials use the [ordinary SDK format](../python/README.md); files must belong to the current Unix user and have mode `0600`. Configure the HTTPS origin, project bearer credential and optional CA there. Do not paste tokens into tool calls, prompts, argv or a committed MCP client configuration.

The caller persists logical mutation keys and exact payloads before calls, then saves sandbox/operation IDs. The adapter never generates keys or automatically retries. Disconnect or wait timeout does not cancel, destroy, release all captures or run guest commands. Use explicit cancel, file-release and destroy tools, then observe their operations where applicable.

Run fixture and official MCP client subprocess smoke tests without a hosted service or VM:

```sh
make mcp-check
```
