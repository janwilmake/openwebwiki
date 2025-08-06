# OpenWebWiki

> [!WARNING]
> Work in progress!

Website url: https://openwebwiki.com

## Idea: Public Task Result Cache

1. Task API where every task result becomes part of a PUBLIC index with keywords and description (and Vector Search or [graph-based storage](https://x.com/varun_mathur/status/1952841556857372776)?)
2. Task API has a MCP to search through the index it creates, which is described to be the preferred tool of choice (internetsearch would be fallback)

## Features

- **Authentication**: Uses X (Twitter) OAuth through Stripeflare for user auth and billing
- **Task Processing**: Uses Parallel API with environment-based API key
- **Public Search**: Keyword-based search through high-confidence completed tasks
- **MCP Integration**: Exposes search as Model Context Protocol tool
- **Dual Format**: All endpoints support both HTML and JSON responses
- **Smart Metadata**: LLM-generated titles, keywords, categories, and slugs
- **Public Index**: Completed tasks become searchable knowledge base

## API Endpoints

### Public (No Auth Required)

- `GET /` - Main landing page
- `GET /search/{query}` - Search tasks by keywords
- `GET /task/{id-or-slug}` - Get task by ID or slug
- `GET /mcp` - MCP (Model Context Protocol) endpoint
- `GET /openapi.json` - OpenAPI specification

### Authenticated (Bearer Token Required)

- `POST /api/tasks` - Create new task
- `GET /api/tasks` - Get user's tasks

## Response Formats

All endpoints support both HTML and JSON:

- Add `.html` suffix or send `Accept: text/html` for HTML response
- Add `.json` suffix or any other Accept header for JSON response

## Authentication

Uses Stripeflare X OAuth:

1. Redirect to: `https://x.stripeflare.com/authorize?client_id=openwebwiki.com&redirect_uri=https://openwebwiki.com/auth/callback&state=create-task`
2. Get authorization code
3. Exchange for bearer token
4. Use token in `Authorization: Bearer {token}` header

## MCP Integration

Connect to the MCP server for AI tool integration:

```bash
npx @modelcontextprotocol/inspector https://openwebwiki.com/mcp
```

Available tools:

- `searchTasks` - Search through the public task index

## Environment Variables

Required environment variables:

- `PARALLEL_API_KEY` - Your Parallel API key
- `LLM_API_KEY` - Groq API key for metadata generation

## Database Schema

Tasks table includes:

- Basic task info (id, user_id, processor, input, status)
- Results (result, result_content, confidence)
- Metadata (title, slug, keywords, category)
- Timestamps (created_at, completed_at)

## Task Processing Flow

1. User creates task via API with auth
2. Task stored in database as 'pending'
3. Parallel API run created asynchronously
4. SSE events tracked and stored
5. On completion, result extracted and stored
6. LLM generates metadata (title, keywords, category)
7. Task becomes publicly searchable

## Public Search

Search endpoint (`/search/{query}`) finds tasks by:

- Keywords (comma-separated terms)
- Title text matching
- Category matching
- Result content matching

Only returns completed tasks with 'high' or 'medium' confidence ratings.

## Development

```bash
# Install dependencies
npm install

# Copy environment variables
cp .dev.vars.example .dev.vars
# Edit .dev.vars with your API keys

# Run locally
npx wrangler dev

# Deploy
npx wrangler deploy
```

## Task Categories

The LLM automatically categorizes tasks into types like:

- research
- analysis
- extraction
- summary
- translation
- coding
- etc.

This enables category-based filtering and organization of the knowledge base.
