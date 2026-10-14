# 0002: no MCP server in the initial scope

Status: Revised for the optional local adapter in issue #113
Date: 2026-09-20 (recording a choice made earlier in this repository's design)

## Context

Agent clients increasingly expect to reach tools through MCP. Shipping an MCP server would make the service reachable by chat clients with no custom tool integration.

It would also add a protocol adapter to maintain alongside the HTTP API, the SDKs, and the CLI, before any of those exist.

## Decision

The initial scope deferred MCP until HTTP and its clients were validated. Main now has the versioned 14-operation contract and conformance-tested SDKs. An optional local stdio adapter is accepted for clients without shell/custom integration, as specified in [the adapter contract](../mcp-adapter.md). It wraps the authenticated Python SDK; HTTP/PostgreSQL remain lifecycle authority.

The interoperability baseline is MCP 2025-11-25 stdio using the pinned maintained official SDK. Tool schema version 1 requires stable caller-owned mutation keys, bounded arguments/results and private operator configuration outside tool arguments. Ordinary HTTP, SDK and CLI clients remain independent. Remote MCP requires a separate authentication/transport decision.

## Consequences

HTTP remains the authoritative public boundary. Local MCP clients can use the optional mapping; we maintain its closed schemas and protocol fixtures alongside the HTTP contract.

This is a sequencing decision, not a judgement that MCP is unnecessary. It should be revisited deliberately rather than by drift; [alternatives](../alternatives.md#revisit-triggers) carries the trigger.

## Alternatives considered

**Ship MCP alongside the first API.** Rejected: it doubles the client surface before the API's own shape has been validated against a working runtime.

**Ship MCP instead of the CLI.** Rejected: humans, scripts, and agents with shell access all need the CLI, and the CLI is also how we test the API by hand.
