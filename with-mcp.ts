interface McpConfig {
  /** defaults to 2025-03-26 */
  protocolVersion?: string;
  promptOperationIds?: string[];
  toolOperationIds?: string[];
  resourceOperationIds?: string[];
}

interface OpenAPIOperation {
  operationId: string;
  summary?: string;
  description?: string;
  parameters?: Array<{
    name: string;
    in: string;
    required?: boolean;
    description?: string;
    schema?: any;
  }>;
  requestBody?: {
    content?: {
      [mediaType: string]: {
        schema?: any;
      };
    };
  };
  responses?: {
    [statusCode: string]: {
      description?: string;
      content?: {
        [mediaType: string]: {
          schema?: any;
        };
      };
    };
  };
}

interface OpenAPISpec {
  paths: {
    [path: string]: {
      [method: string]: OpenAPIOperation;
    };
  };
  components?: {
    schemas?: { [name: string]: any };
  };
}

export function withMcp<TEnv = {}>(
  handler: (
    request: Request,
    env: TEnv,
    ctx: ExecutionContext
  ) => Promise<Response>,
  openapi: OpenAPISpec,
  config: McpConfig
) {
  // Extract operations by operationId
  const allOperations = new Map<
    string,
    { path: string; method: string; operation: OpenAPIOperation }
  >();

  for (const [path, methods] of Object.entries(openapi.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (operation.operationId) {
        allOperations.set(operation.operationId, { path, method, operation });
      }
    }
  }

  return async (
    request: Request,
    env: TEnv,
    ctx: ExecutionContext
  ): Promise<Response> => {
    const url = new URL(request.url);

    // Handle MCP endpoint
    if (url.pathname === "/mcp") {
      // Handle preflight OPTIONS request
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400",
          },
        });
      }

      if (request.method === "POST") {
        const response = await handleMcp(
          request,
          env,
          ctx,
          allOperations,
          config,
          handler
        );

        // Add CORS headers to the response
        const corsHeaders = {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        };

        // Clone the response to add headers
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: {
            ...Object.fromEntries(response.headers.entries()),
            ...corsHeaders,
          },
        });
      }
    }

    // Pass through to original handler
    return handler(request, env, ctx);
  };
}

async function handleMcp(
  request: Request,
  env: any,
  ctx: any,
  allOperations: Map<
    string,
    { path: string; method: string; operation: OpenAPIOperation }
  >,
  config: McpConfig,
  originalHandler: (
    request: Request,
    env: any,
    ctx: ExecutionContext
  ) => Promise<Response>
): Promise<Response> {
  try {
    const message: any = await request.json();

    // Handle initialize
    if (message.method === "initialize") {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: config.protocolVersion || "2025-03-26",
            capabilities: {
              ...(config.promptOperationIds.length > 0 && { prompts: {} }),
              ...(config.resourceOperationIds.length > 0 && { resources: {} }),
              ...(config.toolOperationIds.length > 0 && { tools: {} }),
            },
            serverInfo: {
              name: "OpenWebWiki-MCP-Server",
              version: "1.0.0",
            },
          },
        }),
        {
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Handle initialized notification
    if (message.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }

    // Handle tools/list
    if (message.method === "tools/list") {
      const tools = config.toolOperationIds
        .map((opId) => {
          const op = allOperations.get(opId);
          if (!op) return null;

          return {
            name: opId,
            title: op.operation.summary || opId,
            description: op.operation.description,
            inputSchema: extractInputSchema(op.operation),
          };
        })
        .filter(Boolean);

      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: { tools },
        }),
        {
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Handle tools/call
    if (message.method === "tools/call") {
      const { name, arguments: args } = message.params;
      const op = allOperations.get(name);

      if (!op || !config.toolOperationIds.includes(name)) {
        return createError(message.id, -32602, `Unknown tool: ${name}`);
      }

      try {
        const apiResponse = await executeOperation(
          op,
          args,
          originalHandler,
          request,
          env,
          ctx
        );
        const content = await convertResponseToToolContent(apiResponse);

        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            result: {
              content,
              isError: !apiResponse.ok,
            },
          }),
          {
            headers: { "Content-Type": "application/json" },
          }
        );
      } catch (error) {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            result: {
              content: [
                {
                  type: "text",
                  text: `Error executing tool: ${error.message}`,
                },
              ],
              isError: true,
            },
          }),
          {
            headers: { "Content-Type": "application/json" },
          }
        );
      }
    }

    return createError(
      message.id,
      -32601,
      `Method not found: ${message.method}`
    );
  } catch (error) {
    return createError(null, -32700, "Parse error");
  }
}

function extractInputSchema(operation: OpenAPIOperation) {
  // Start with basic object schema
  const schema: any = {
    type: "object",
    properties: {},
    required: [],
  };

  // Add parameters as properties
  if (operation.parameters) {
    for (const param of operation.parameters) {
      schema.properties[param.name] = param.schema || { type: "string" };
      if (param.required) {
        schema.required.push(param.name);
      }
    }
  }

  // Merge request body schema
  if (operation.requestBody?.content?.["application/json"]?.schema) {
    const bodySchema = operation.requestBody.content["application/json"].schema;
    if (bodySchema.properties) {
      Object.assign(schema.properties, bodySchema.properties);
    }
    if (bodySchema.required) {
      schema.required.push(...bodySchema.required);
    }
  }

  return schema;
}

async function executeOperation(
  op: { path: string; method: string; operation: OpenAPIOperation },
  args: any,
  originalHandler: (
    request: Request,
    env: any,
    ctx: ExecutionContext
  ) => Promise<Response>,
  originalRequest: Request,
  env: any,
  ctx: any
): Promise<Response> {
  // Build the API request URL
  let url = op.path;
  const queryParams = new URLSearchParams();
  const bodyData: any = {};

  // Handle parameters
  if (op.operation.parameters) {
    for (const param of op.operation.parameters) {
      const value = args[param.name];
      if (value !== undefined) {
        if (param.in === "path") {
          url = url.replace(`{${param.name}}`, encodeURIComponent(value));
        } else if (param.in === "query") {
          queryParams.set(param.name, value);
        }
      }
    }
  }

  // Add remaining args to body
  Object.assign(bodyData, args);

  // Build the final URL
  const baseUrl = new URL(originalRequest.url).origin;
  const finalUrl = new URL(url, baseUrl);
  if (queryParams.toString()) {
    finalUrl.search = queryParams.toString();
  }

  const headers = {
    accept: "application/json",
    "content-type": "application/json",
  };

  // Create the API request
  const apiRequest = new Request(finalUrl.toString(), {
    method: op.method.toUpperCase(),
    headers,
    ...(op.method.toUpperCase() !== "GET" &&
      Object.keys(bodyData).length > 0 && {
        body: JSON.stringify(bodyData),
      }),
  });

  return originalHandler(apiRequest, env, ctx);
}

async function convertResponseToToolContent(response: Response) {
  const text = await response.text();

  return [
    {
      type: "text" as const,
      text,
    },
  ];
}

function createError(id: any, code: number, message: string) {
  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id,
      error: { code, message },
    }),
    {
      status: 200, // JSON-RPC errors use 200 status
      headers: { "Content-Type": "application/json" },
    }
  );
}
