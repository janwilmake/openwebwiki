//@ts-check
/// <reference lib="esnext" />
/// <reference types="@cloudflare/workers-types" />
import { DurableObject } from "cloudflare:workers";
import { withMcp } from "./with-mcp";
import openapi from "./openapi.json";

interface Env {
  TASK_MANAGER: DurableObjectNamespace<TaskManager>;
  TASK_RUNNER: DurableObjectNamespace<TaskRunner>;
  PARALLEL_API_KEY: string;
  LLM_API_KEY: string;
}

interface TaskData {
  input: string;
  processor: string;
  taskSpec?: object;
}

interface AuthUser {
  x_user_id: string;
  username: string;
  name: string;
  profile_image_url?: string;
  verified: boolean;
  balance: number;
  client_balance: number;
}

interface TaskRow extends Record<string, SqlStorageValue> {
  id: string;
  processor: string;
  input: string;
  task_spec: string | null;
  run_id: string | null;
  status: string;
  created_at: number;
  completed_at: number | null;
  result: string | null;
  result_content: string | null;
  confidence: string | null;
  title: string | null;
  slug: string | null;
  keywords: string | null;
  category: string | null;
  user_id: string;
}

interface EventRow extends Record<string, SqlStorageValue> {
  event_type: string;
  event_data: string;
  timestamp: number;
}

interface TaskRunResult {
  run: {
    run_id: string;
    status: string;
    is_active: boolean;
    processor: string;
    metadata?: any;
    created_at: string;
    modified_at: string;
  };
  output: {
    basis: Array<{
      field: string;
      citations: Array<{
        title?: string;
        url: string;
        excerpts?: string[];
      }>;
      reasoning: string;
      confidence?: string;
    }>;
    type: "json" | "text";
    content: any;
  };
}

interface GroqResponse {
  choices: Array<{
    message: {
      content: string;
    };
  }>;
}

interface TaskMetadata {
  title: string;
  slug: string;
  keywords: string;
  category: string;
}

export default {
  fetch: withMcp(
    async (
      request: Request,
      env: Env,
      ctx: ExecutionContext
    ): Promise<Response> => {
      const url = new URL(request.url);
      const taskManagerId = env.TASK_MANAGER.idFromName("main");
      const taskManager = env.TASK_MANAGER.get(taskManagerId);

      // Handle auth verification
      const authResult = await verifyAuth(request);

      // Public endpoints (no auth required)
      if (url.pathname.startsWith("/search/")) {
        const query = decodeURIComponent(url.pathname.split("/search/")[1]);
        return taskManager.searchTasks(query, getResponseFormat(request, url));
      }

      if (url.pathname.startsWith("/task/")) {
        const taskIdentifier = url.pathname.split("/")[2];
        return taskManager.getPublicTask(
          taskIdentifier,
          getResponseFormat(request, url)
        );
      }

      if (url.pathname === "/openapi.json") {
        return new Response(JSON.stringify(openapi, null, 2), {
          headers: { "Content-Type": "application/json" },
        });
      }

      if (url.pathname === "/" || url.pathname === "/index.html") {
        return new Response(await getIndexHTML(), {
          headers: { "Content-Type": "text/html" },
        });
      }

      // Protected endpoints (require auth)
      if (!authResult.success) {
        return new Response(
          JSON.stringify({ error: "Authentication required" }),
          {
            status: 401,
            headers: { "Content-Type": "application/json" },
          }
        );
      }

      const user = authResult.user!;

      if (url.pathname === "/api/tasks" && request.method === "POST") {
        const taskData = (await request.json()) as TaskData;
        return taskManager.createTask(taskData, user, env.PARALLEL_API_KEY);
      }

      if (url.pathname === "/api/tasks" && request.method === "GET") {
        return taskManager.getUserTasks(user.x_user_id);
      }

      return new Response("Not found", { status: 404 });
    },
    openapi,
    {
      protocolVersion: "2025-03-26",
      promptOperationIds: [],
      toolOperationIds: ["searchTasks"],
      resourceOperationIds: [],
    }
  ),
};

async function verifyAuth(
  request: Request
): Promise<{ success: boolean; user?: AuthUser }> {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return { success: false };
  }

  const token = authHeader.substring(7);

  try {
    const response = await fetch("https://x.stripeflare.com/user", {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      return { success: false };
    }

    const user = (await response.json()) as AuthUser;
    return { success: true, user };
  } catch (error) {
    return { success: false };
  }
}

function getResponseFormat(request: Request, url: URL): "html" | "json" {
  const acceptHeader = request.headers.get("Accept") || "";
  const hasJsonExtension = url.pathname.endsWith(".json");
  const hasHtmlExtension = url.pathname.endsWith(".html");

  if (hasJsonExtension) return "json";
  if (hasHtmlExtension) return "html";
  if (acceptHeader.includes("text/html")) return "html";

  return "json";
}

export class TaskManager extends DurableObject {
  private sql: SqlStorage;
  env: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    this.env = env;

    // Initialize tables
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        processor TEXT NOT NULL,
        input TEXT NOT NULL,
        task_spec TEXT,
        run_id TEXT,
        status TEXT DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        completed_at INTEGER,
        result TEXT,
        result_content TEXT,
        confidence TEXT,
        title TEXT,
        slug TEXT,
        keywords TEXT,
        category TEXT
      )
    `);

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS task_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        event_data TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        FOREIGN KEY (task_id) REFERENCES tasks (id)
      )
    `);

    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_tasks_slug ON tasks (slug)`);
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks (user_id)`
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_tasks_keywords ON tasks (keywords)`
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_tasks_category ON tasks (category)`
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_tasks_confidence ON tasks (confidence)`
    );
  }

  async createTask(
    taskData: TaskData,
    user: AuthUser,
    apiKey: string
  ): Promise<Response> {
    const taskId = crypto.randomUUID();
    const now = Date.now();

    // Check if user has sufficient balance (minimum $1 for any processor)
    if (user.client_balance < 1) {
      return new Response(
        JSON.stringify({
          error: "Insufficient balance. Minimum $1 required.",
        }),
        {
          status: 402,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Store task in database
    this.sql.exec(
      `INSERT INTO tasks (id, user_id, processor, input, task_spec, created_at) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      taskId,
      user.x_user_id,
      taskData.processor,
      taskData.input,
      taskData.taskSpec ? JSON.stringify(taskData.taskSpec) : null,
      now
    );

    // Create a task runner DO for this specific task
    const taskRunnerId = this.env.TASK_RUNNER.idFromName(taskId);
    const taskRunner = this.env.TASK_RUNNER.get(taskRunnerId);

    // Start the task runner (fire and forget)
    taskRunner.runTask(taskId, taskData, apiKey);

    return new Response(JSON.stringify({ taskId, status: "started" }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  async getUserTasks(userId: string): Promise<Response> {
    const result = this.sql.exec(
      `
      SELECT id, processor, status, created_at, completed_at, title, slug, keywords, category,
             substr(input, 1, 100) as input_preview
      FROM tasks 
      WHERE user_id = ?
      ORDER BY created_at DESC
    `,
      userId
    );

    const tasks = result.toArray().map((row: any) => ({
      id: row.id,
      processor: row.processor,
      status: row.status,
      title: row.title,
      slug: row.slug,
      keywords: row.keywords,
      category: row.category,
      createdAt: new Date(row.created_at).toISOString(),
      completedAt: row.completed_at
        ? new Date(row.completed_at).toISOString()
        : null,
      inputPreview: row.input_preview,
    }));

    return new Response(JSON.stringify(tasks), {
      headers: { "Content-Type": "application/json" },
    });
  }

  async searchTasks(query: string, format: "html" | "json"): Promise<Response> {
    // Search by keywords, title, or category with high confidence
    const result = this.sql.exec(
      `
      SELECT id, title, slug, keywords, category, result_content, confidence, created_at
      FROM tasks 
      WHERE status = 'completed' 
        AND confidence IN ('high', 'medium')
        AND (
          keywords LIKE ? OR 
          title LIKE ? OR 
          category LIKE ? OR
          result_content LIKE ?
        )
      ORDER BY 
        CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
        created_at DESC
      LIMIT 50
    `,
      `%${query}%`,
      `%${query}%`,
      `%${query}%`,
      `%${query}%`
    );

    const tasks = result.toArray().map((row: any) => ({
      id: row.id,
      title: row.title,
      slug: row.slug,
      keywords: row.keywords,
      category: row.category,
      result_content: row.result_content,
      confidence: row.confidence,
      createdAt: new Date(row.created_at).toISOString(),
    }));

    if (format === "html") {
      const html = generateSearchHTML(query, tasks);
      return new Response(html, {
        headers: { "Content-Type": "text/html" },
      });
    }

    return new Response(JSON.stringify({ query, results: tasks }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  async getPublicTask(
    identifier: string,
    format: "html" | "json"
  ): Promise<Response> {
    // Try to find by slug first, then by ID
    let result = this.sql.exec<TaskRow>(
      `
      SELECT * FROM tasks WHERE slug = ? AND status = 'completed'
    `,
      identifier
    );

    let taskRows = result.toArray() as TaskRow[];

    if (taskRows.length === 0) {
      result = this.sql.exec<TaskRow>(
        `
        SELECT * FROM tasks WHERE id = ? AND status = 'completed'
      `,
        identifier
      );
      taskRows = result.toArray() as TaskRow[];
    }

    if (taskRows.length === 0) {
      return new Response(
        format === "html"
          ? "Task not found"
          : JSON.stringify({ error: "Task not found" }),
        {
          status: 404,
          headers: {
            "Content-Type":
              format === "html" ? "text/html" : "application/json",
          },
        }
      );
    }

    const task = taskRows[0];

    const taskData = {
      id: task.id,
      title: task.title,
      slug: task.slug,
      keywords: task.keywords,
      category: task.category,
      processor: task.processor,
      input: task.input,
      result_content: task.result_content,
      confidence: task.confidence,
      createdAt: new Date(task.created_at).toISOString(),
      completedAt: task.completed_at
        ? new Date(task.completed_at).toISOString()
        : null,
    };

    if (format === "html") {
      const html = generateTaskHTML(taskData);
      return new Response(html, {
        headers: { "Content-Type": "text/html" },
      });
    }

    return new Response(JSON.stringify(taskData), {
      headers: { "Content-Type": "application/json" },
    });
  }

  async addEvent(
    taskId: string,
    eventType: string,
    eventData: any
  ): Promise<void> {
    this.sql.exec(
      `INSERT INTO task_events (task_id, event_type, event_data, timestamp) 
       VALUES (?, ?, ?, ?)`,
      taskId,
      eventType,
      JSON.stringify(eventData),
      Date.now()
    );
  }

  async updateTaskRunId(taskId: string, runId: string): Promise<void> {
    this.sql.exec(`UPDATE tasks SET run_id = ? WHERE id = ?`, runId, taskId);
  }

  async updateTaskStatus(
    taskId: string,
    status: string,
    result?: any
  ): Promise<void> {
    const completedAt =
      status === "completed" || status === "failed" ? Date.now() : null;
    this.sql.exec(
      `UPDATE tasks SET status = ?, completed_at = ?, result = ? WHERE id = ?`,
      status,
      completedAt,
      result ? JSON.stringify(result) : null,
      taskId
    );
  }

  async updateTaskResult(
    taskId: string,
    result: TaskRunResult,
    resultContent: string | object,
    confidence: string
  ): Promise<void> {
    this.sql.exec(
      `UPDATE tasks SET result = ?, result_content = ?, confidence = ? WHERE id = ?`,
      JSON.stringify(result),
      typeof resultContent === "string"
        ? resultContent
        : JSON.stringify(resultContent),
      confidence,
      taskId
    );
  }

  async updateTaskMetadata(
    taskId: string,
    metadata: TaskMetadata
  ): Promise<void> {
    this.sql.exec(
      `UPDATE tasks SET title = ?, slug = ?, keywords = ?, category = ? WHERE id = ?`,
      metadata.title,
      metadata.slug,
      metadata.keywords,
      metadata.category,
      taskId
    );
  }

  async generateSlug(baseSlug: string): Promise<string> {
    let slug = baseSlug;
    let counter = 1;

    while (true) {
      const result = this.sql.exec(
        `SELECT COUNT(*) as count FROM tasks WHERE slug = ?`,
        slug
      );
      const count = result.toArray()[0].count as number;
      if (count === 0) return slug;
      slug = `${baseSlug}-${counter}`;
      counter++;
    }
  }

  private slugify(text: string): string {
    return text
      .toLowerCase()
      .trim()
      .replace(/[^\w\s-]/g, "")
      .replace(/[\s_-]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  async generateTaskMetadata(
    taskId: string,
    input: string,
    result: TaskRunResult
  ): Promise<void> {
    try {
      const prompt = `Based on this task input and result, generate metadata:

INPUT: ${input}

RESULT: ${JSON.stringify(result, null, 2)}

Please respond with a JSON object containing:
- title: A concise, descriptive title for this task (max 100 chars)
- keywords: Comma-separated keywords that describe this task (max 200 chars)  
- category: A single category that best describes this task type (e.g., "research", "analysis", "extraction", "summary", "translation", "coding", etc.)

Format your response as valid JSON only, no additional text.`;

      const response = await fetch(
        "https://api.groq.com/openai/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.env.LLM_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "gpt-4o-mini",
            messages: [{ role: "user", content: prompt }],
            max_tokens: 500,
            temperature: 0.7,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(`Groq API error: ${response.status}`);
      }

      const data = (await response.json()) as GroqResponse;
      const content = data.choices[0]?.message?.content;

      if (!content) {
        throw new Error("No content in Groq response");
      }

      const metadata = JSON.parse(content) as {
        title: string;
        keywords: string;
        category: string;
      };

      const baseSlug = this.slugify(metadata.title);
      const slug = await this.generateSlug(baseSlug);

      await this.updateTaskMetadata(taskId, {
        title: metadata.title,
        slug,
        keywords: metadata.keywords,
        category: metadata.category,
      });

      await this.addEvent(taskId, "metadata_generated", {
        title: metadata.title,
        slug,
        keywords: metadata.keywords,
        category: metadata.category,
      });
    } catch (error) {
      await this.addEvent(taskId, "metadata_generation_error", {
        message: `Failed to generate metadata: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
      });
    }
  }
}

export class TaskRunner extends DurableObject {
  env: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.env = env;
  }

  async runTask(
    taskId: string,
    taskData: TaskData,
    apiKey: string
  ): Promise<void> {
    try {
      const taskManagerId = this.env.TASK_MANAGER.idFromName("main");
      const taskManager = this.env.TASK_MANAGER.get(taskManagerId);

      const createPayload: any = {
        input: taskData.input,
        processor: taskData.processor,
        enable_events: true,
      };

      if (taskData.taskSpec) {
        createPayload.task_spec = taskData.taskSpec;
      }

      const createResponse = await fetch(
        "https://api.parallel.ai/v1/tasks/runs",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": apiKey,
            "parallel-beta": "events-sse-2025-07-24",
          },
          body: JSON.stringify(createPayload),
        }
      );

      if (!createResponse.ok) {
        const error = await createResponse.text();
        await taskManager.addEvent(taskId, "error", {
          message: `Failed to create task: ${error}`,
        });
        await taskManager.updateTaskStatus(taskId, "failed");
        return;
      }

      const taskRun = await createResponse.json();
      const runId = taskRun.run_id;

      await taskManager.updateTaskRunId(taskId, runId);
      await taskManager.addEvent(taskId, "task_created", taskRun);
      await taskManager.updateTaskStatus(taskId, "running");

      // Start listening to SSE events
      const eventsResponse = await fetch(
        `https://api.parallel.ai/v1beta/tasks/runs/${runId}/events`,
        {
          headers: {
            "x-api-key": apiKey,
            "Content-Type": "text/event-stream",
          },
        }
      );

      if (!eventsResponse.ok) {
        await taskManager.addEvent(taskId, "error", {
          message: "Failed to connect to SSE stream",
        });
        await taskManager.updateTaskStatus(taskId, "failed");
        return;
      }

      // Process SSE stream
      const reader = eventsResponse.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      if (!reader) {
        await taskManager.addEvent(taskId, "error", {
          message: "No readable stream",
        });
        await taskManager.updateTaskStatus(taskId, "failed");
        return;
      }

      try {
        while (true) {
          const { done, value } = await reader.read();

          if (done) {
            await this.checkFinalStatus(taskId, runId, apiKey, taskManager);
            break;
          }

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                const eventData = JSON.parse(line.slice(6));
                await taskManager.addEvent(taskId, "sse_event", eventData);

                if (eventData.type === "status") {
                  if (eventData.status === "completed") {
                    await this.fetchAndStoreResult(
                      taskId,
                      runId,
                      apiKey,
                      taskData.input,
                      taskManager
                    );
                    return;
                  } else if (eventData.status === "failed") {
                    await taskManager.updateTaskStatus(taskId, "failed");
                    return;
                  }
                }
              } catch (e) {
                await taskManager.addEvent(taskId, "parse_error", {
                  message: `Failed to parse SSE event: ${
                    e instanceof Error ? e.message : "Unknown error"
                  }`,
                  line: line,
                });
              }
            }
          }
        }
      } finally {
        reader.releaseLock();
      }
    } catch (error) {
      const taskManagerId = this.env.TASK_MANAGER.idFromName("main");
      const taskManager = this.env.TASK_MANAGER.get(taskManagerId);
      await taskManager.addEvent(taskId, "error", {
        message: error instanceof Error ? error.message : "Unknown error",
      });
      await taskManager.updateTaskStatus(taskId, "failed");
    }
  }

  private async fetchAndStoreResult(
    taskId: string,
    runId: string,
    apiKey: string,
    input: string,
    taskManager: DurableObjectStub<TaskManager>
  ): Promise<void> {
    try {
      const resultResponse = await fetch(
        `https://api.parallel.ai/v1/tasks/runs/${runId}/result`,
        {
          headers: { "x-api-key": apiKey },
        }
      );

      if (resultResponse.ok) {
        const result = (await resultResponse.json()) as TaskRunResult;
        const resultContent = result.output.content;
        const confidence = this.extractConfidence(result.output.basis);

        await taskManager.updateTaskResult(
          taskId,
          result,
          resultContent,
          confidence
        );
        await taskManager.addEvent(taskId, "result", result);
        await taskManager.updateTaskStatus(taskId, "completed", result);
        await taskManager.generateTaskMetadata(taskId, input, result);
      } else {
        const errorText = await resultResponse.text();
        await taskManager.addEvent(taskId, "result_error", {
          message: `Failed to fetch result: ${errorText}`,
          status: resultResponse.status,
        });
        await taskManager.updateTaskStatus(taskId, "failed");
      }
    } catch (error) {
      await taskManager.addEvent(taskId, "result_error", {
        message: `Error fetching result: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
      });
      await taskManager.updateTaskStatus(taskId, "failed");
    }
  }

  private async checkFinalStatus(
    taskId: string,
    runId: string,
    apiKey: string,
    taskManager: DurableObjectStub<TaskManager>
  ): Promise<void> {
    try {
      const statusResponse = await fetch(
        `https://api.parallel.ai/v1/tasks/runs/${runId}`,
        {
          headers: { "x-api-key": apiKey },
        }
      );

      if (statusResponse.ok) {
        const status = await statusResponse.json();
        await taskManager.addEvent(taskId, "final_status_check", status);

        if (status.status === "completed") {
          // Get task input for metadata generation
          const taskResult = taskManager.sql.exec(
            `SELECT input FROM tasks WHERE id = ?`,
            taskId
          );
          const taskRows = taskResult.toArray() as Array<{ input: string }>;
          const input = taskRows[0]?.input || "";

          await this.fetchAndStoreResult(
            taskId,
            runId,
            apiKey,
            input,
            taskManager
          );
        } else if (status.status === "failed") {
          await taskManager.updateTaskStatus(taskId, "failed");
        } else {
          await taskManager.updateTaskStatus(taskId, status.status);
        }
      } else {
        await taskManager.addEvent(taskId, "status_check_error", {
          message: "Failed to check final status",
        });
        await taskManager.updateTaskStatus(taskId, "unknown");
      }
    } catch (error) {
      await taskManager.addEvent(taskId, "status_check_error", {
        message: `Error checking final status: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
      });
      await taskManager.updateTaskStatus(taskId, "unknown");
    }
  }

  private extractConfidence(basis: TaskRunResult["output"]["basis"]): string {
    const confidenceLevels = basis
      .map((b) => b.confidence)
      .filter((c): c is string => c !== undefined && c !== null);

    if (confidenceLevels.length === 0) return "unknown";

    if (confidenceLevels.includes("high")) return "high";
    if (confidenceLevels.includes("medium")) return "medium";
    if (confidenceLevels.includes("low")) return "low";

    return confidenceLevels[0] || "unknown";
  }
}

function generateSearchHTML(query: string, tasks: any[]): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search Results: ${query} - OpenWebWiki</title>
    <style>
        body { font-family: system-ui; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }
        .search-result { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .title { font-size: 1.2em; font-weight: bold; margin-bottom: 8px; }
        .meta { color: #666; font-size: 0.9em; margin-bottom: 12px; }
        .content { line-height: 1.6; }
        .confidence-high { border-left: 4px solid #10b981; }
        .confidence-medium { border-left: 4px solid #f59e0b; }
        .keywords { background: #f3f4f6; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; margin: 0 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Search Results for "${query}"</h1>
        <p>Found ${tasks.length} results</p>
    </div>
    
    ${tasks
      .map(
        (task) => `
        <div class="search-result confidence-${task.confidence}">
            <div class="title">
                <a href="/task/${task.slug || task.id}">${
          task.title || "Untitled Task"
        }</a>
            </div>
            <div class="meta">
                Category: <strong>${
                  task.category || "Uncategorized"
                }</strong> | 
                Confidence: <strong>${task.confidence}</strong> |
                Created: ${new Date(task.createdAt).toLocaleDateString()}
            </div>
            <div class="content">
                ${
                  typeof task.result_content === "string"
                    ? task.result_content.substring(0, 500) +
                      (task.result_content.length > 500 ? "..." : "")
                    : JSON.stringify(task.result_content).substring(0, 500) +
                      "..."
                }
            </div>
            <div style="margin-top: 12px;">
                ${
                  task.keywords
                    ? task.keywords
                        .split(",")
                        .map(
                          (k: string) =>
                            `<span class="keywords">${k.trim()}</span>`
                        )
                        .join("")
                    : ""
                }
            </div>
        </div>
    `
      )
      .join("")}
</body>
</html>`;
}

function generateTaskHTML(task: any): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${task.title || "Task"} - OpenWebWiki</title>
    <style>
        body { font-family: system-ui; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }
        .meta { background: #f9fafb; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .content { line-height: 1.6; background: white; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .keywords { background: #f3f4f6; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; margin: 0 4px; }
        .input-section { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .confidence-high { border-left: 4px solid #10b981; }
        .confidence-medium { border-left: 4px solid #f59e0b; }
        .confidence-low { border-left: 4px solid #ef4444; }
    </style>
</head>
<body>
    <div class="header">
        <h1>${task.title || "Untitled Task"}</h1>
        <div class="meta confidence-${task.confidence}">
            <strong>Category:</strong> ${task.category || "Uncategorized"} | 
            <strong>Processor:</strong> ${task.processor} |
            <strong>Confidence:</strong> ${task.confidence} |
            <strong>Created:</strong> ${new Date(
              task.createdAt
            ).toLocaleDateString()}
            ${
              task.completedAt
                ? ` | <strong>Completed:</strong> ${new Date(
                    task.completedAt
                  ).toLocaleDateString()}`
                : ""
            }
        </div>
        
        ${
          task.keywords
            ? `
        <div style="margin-top: 15px;">
            <strong>Keywords:</strong>
            ${task.keywords
              .split(",")
              .map((k: string) => `<span class="keywords">${k.trim()}</span>`)
              .join("")}
        </div>`
            : ""
        }
    </div>

    <div class="input-section">
        <h3>Original Input</h3>
        <pre>${task.input}</pre>
    </div>

    <div class="content">
        <h3>Result</h3>
        ${
          typeof task.result_content === "string"
            ? `<div>${task.result_content.replace(/\n/g, "<br>")}</div>`
            : `<pre>${JSON.stringify(task.result_content, null, 2)}</pre>`
        }
    </div>

    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; color: #666;">
        <a href="/task/${task.id}.json">View Raw JSON</a>
    </div>
</body>
</html>`;
}

async function getIndexHTML(): Promise<string> {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenWebWiki - Task API</title>
    <style>
        body { font-family: system-ui; max-width: 1200px; margin: 0 auto; padding: 20px; line-height: 1.6; }
        .header { text-align: center; margin-bottom: 40px; }
        .section { margin-bottom: 40px; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .auth-section { background: #fef3c7; }
        .search-section { background: #ecfdf5; }
        .api-section { background: #eff6ff; }
        code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
        pre { background: #f3f4f6; padding: 15px; border-radius: 8px; overflow-x: auto; }
        .btn { display: inline-block; padding: 10px 20px; background: #3b82f6; color: white; text-decoration: none; border-radius: 6px; margin: 5px; }
        .search-form { margin: 20px 0; }
        .search-form input { padding: 10px; border: 1px solid #ddd; border-radius: 4px; width: 300px; }
        .search-form button { padding: 10px 20px; background: #10b981; color: white; border: none; border-radius: 4px; margin-left: 10px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 OpenWebWiki</h1>
        <p>Task API with Public Search & Knowledge Index</p>
    </div>

    <div class="section auth-section">
        <h2>🔐 Authentication Required</h2>
        <p>To create and manage tasks, you need to authenticate using X (Twitter) OAuth through Stripeflare.</p>
        <a href="https://x.stripeflare.com/authorize?client_id=openwebwiki.com&redirect_uri=https://openwebwiki.com/auth/callback&state=create-task" class="btn">Login with X</a>
    </div>

    <div class="section search-section">
        <h2>🔍 Search Public Tasks</h2>
        <p>Search through completed tasks with high confidence ratings:</p>
        
        <div class="search-form">
            <input type="text" id="searchQuery" placeholder="Enter search query..." />
            <button onclick="search()">Search</button>
        </div>
        
        <p>Examples:</p>
        <ul>
            <li><a href="/search/research">research</a></li>
            <li><a href="/search/analysis">analysis</a></li>
            <li><a href="/search/summary">summary</a></li>
        </ul>
    </div>

    <div class="section api-section">
        <h2>🔧 API Documentation</h2>
        
        <h3>Public Endpoints</h3>
        <ul>
            <li><code>GET /search/{query}</code> - Search tasks by keywords</li>
            <li><code>GET /task/{id-or-slug}</code> - Get task by ID or slug</li>
            <li><code>GET /mcp</code> - MCP (Model Context Protocol) endpoint</li>
            <li><code>GET /openapi.json</code> - OpenAPI specification</li>
        </ul>

        <h3>Authenticated Endpoints</h3>
        <ul>
            <li><code>POST /api/tasks</code> - Create new task</li>
            <li><code>GET /api/tasks</code> - Get user's tasks</li>
        </ul>

        <h3>Response Formats</h3>
        <p>All endpoints support both HTML and JSON formats:</p>
        <ul>
            <li>Add <code>.html</code> suffix or send <code>Accept: text/html</code> for HTML</li>
            <li>Add <code>.json</code> suffix or any other Accept header for JSON</li>
        </ul>

        <h3>MCP Integration</h3>
        <p>Connect to our MCP server for AI tool integration:</p>
        <pre>npx @modelcontextprotocol/inspector https://openwebwiki.com/mcp</pre>
        
        <a href="/openapi.json" class="btn">View OpenAPI Spec</a>
    </div>

    <script>
        function search() {
            const query = document.getElementById('searchQuery').value.trim();
            if (query) {
                window.location.href = '/search/' + encodeURIComponent(query);
            }
        }
        
        document.getElementById('searchQuery').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                search();
            }
        });
    </script>
</body>
</html>`;
}
