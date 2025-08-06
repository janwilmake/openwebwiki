Website url: https://openwebwiki.com

Task API where every task result becomes part of a PUBLIC index with keywords and description

- Uses https://xmoney.stripeflare.com to put it behind authwall and give users balance
- Use PARALLEL_API_KEY from env instead of form
- Add column category (determined by LLM)
- Task is available by slug `/task/{slug}` as well as by ID `/task/{id}`
- Exposes PUBLIC keyword based search `/search/%s` api endpoint that returns tasks with high confidence (not the result column, just the result_content)
- Has static `openapi.json` file in root
- Exposes the search endpoint as public MCP too (/mcp): https://uithub.com/janwilmake/with-mcp
- Update the Task API such that it uses the MCP (see https://docs.parallel.ai/features/mcp-tool-call.md) to search through the index it creates

For every page:

- if accept header includes text/html or .html is appended to pathname, returns it as html
- if not, or if .json is appended to pathname, return the raw json of the row
