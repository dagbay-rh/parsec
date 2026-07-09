# MCP & Tool Setup Guide

Reference for setting up external tool access required by the `parsec-impl` skill.

## JIRA Access (Required)

The skill uses the **Atlassian MCP Server** to fetch JIRA issues automatically.

### Setup

1. Open **Cursor Settings > MCP**
2. Add a new MCP server:
   - **Name**: `Atlassian-MCP-Server`
   - **Package**: `@anthropic/atlassian-mcp-server` (or your org's preferred Atlassian MCP)
3. When prompted, authenticate with your Atlassian account
4. Verify by asking Cursor: _"List my accessible Atlassian resources"_

### Fallback

If you cannot configure the MCP, paste the JIRA issue content directly when
prompted. Include: summary, description, acceptance criteria, and any custom
fields relevant to the task.

### Verifying Access

The skill runs `getAccessibleAtlassianResources` as a health check. If this
call fails, the skill will prompt you with setup instructions or ask for
manual input.

## Google Docs / Drive Access

The skill supports three methods for fetching Google Doc content (tried in this
order):

### Option 1: GWS CLI / SDK (Recommended)

If your team uses the Google Workspace CLI:

```bash
# Check if installed
which gws

# Authenticate (one-time)
gws auth login

# Fetch a document as plain text
gws docs get <document-id> --format=text

# The document ID is the long string in the URL:
# https://docs.google.com/document/d/<DOCUMENT-ID>/edit
```

**Installation** (if not already installed):
- Via pip: `pip install gws-cli`
- Via your organization's internal tooling / SDK distribution
- Consult your team's GWS SDK documentation for org-specific setup

### Option 2: Google Drive MCP Server

Add a Google Drive MCP server to Cursor:

1. Open **Cursor Settings > MCP**
2. Add a new MCP server for Google Drive (e.g. `@anthropic/google-drive-mcp`
   or your org's equivalent)
3. Authenticate with your Google account
4. The skill will detect the MCP server and use it to fetch documents

### Option 3: Manual Paste

Copy the relevant content from the Google Doc and paste it when prompted. This
always works as a fallback.

## Confluence Access

Confluence access is provided by the **same Atlassian MCP Server** used for
JIRA. No additional setup is needed. The skill uses `getConfluencePage` and
`searchConfluenceUsingCql` to fetch pages.

## Other URLs

The skill uses `WebFetch` to retrieve content from arbitrary URLs. No setup
required — this works for public pages. For authenticated/private pages, paste
the content manually.
