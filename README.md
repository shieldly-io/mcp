# @shieldly/mcp

**AI-Powered Security Analysis for AWS — official MCP server.**

Gives any MCP-compatible AI assistant (Claude Code, Claude Desktop, Cursor,
etc.) two tools to analyze AWS IAM policies and CloudFormation templates for
security risks — privilege escalation paths, wildcards, and other
over-permissive access. Powered by [Shieldly](https://www.shieldly.io).

## Setup

Add to your MCP client config (e.g. Claude Desktop's `claude_desktop_config.json`,
or Claude Code's `.mcp.json`):

```json
{
  "mcpServers": {
    "shieldly": {
      "command": "npx",
      "args": ["-y", "@shieldly/mcp"]
    }
  }
}
```

## Try it free — no account needed

Both tools run in demo mode without an API key (rate-limited, no signup). For
higher limits, set `SHIELDLY_API_KEY`:

```json
{
  "mcpServers": {
    "shieldly": {
      "command": "npx",
      "args": ["-y", "@shieldly/mcp"],
      "env": { "SHIELDLY_API_KEY": "sk_live_..." }
    }
  }
}
```

Get an API key (Builder plan or above): https://www.shieldly.io/app/api

## Tools

### `analyze_iam_policy`

Analyzes an IAM identity policy, or a cross-account trust+identity pair.

| Argument | Type | Description |
| --- | --- | --- |
| `policy` | string | The IAM policy JSON as a string. |
| `policyType` | `identity` \| `cross_account` | Defaults to `identity`. |

### `analyze_cloudformation_template`

Analyzes a CloudFormation template — extracts IAM roles/policies and flags
over-permissive access.

| Argument | Type | Description |
| --- | --- | --- |
| `template` | string | The CloudFormation template JSON as a string. |

## Also available as

- [CLI](https://www.npmjs.com/package/@shieldly/cli)
- [VS Code extension](https://marketplace.visualstudio.com/items?itemName=shieldly.shieldly)
- [GitHub Action](https://github.com/shieldly-io/action)
- [CDK Guard](https://www.npmjs.com/package/@shieldly/cdk-guard)
- [Web app](https://www.shieldly.io)

## License

MIT
