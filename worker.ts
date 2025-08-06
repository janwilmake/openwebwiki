//@ts-check
/// <reference lib="esnext" />
/// <reference types="@cloudflare/workers-types" />
import { DurableObject } from "cloudflare:workers";

interface Env {
  TASK_MANAGER: DurableObjectNamespace<TaskManager>;
  TASK_RUNNER: DurableObjectNamespace<TaskRunner>;
  LLM_API_KEY: string;
}

interface TaskData {
  apiKey: string;
  processor: string;
  input: string;
  taskSpec?: object;
}

interface TaskRow extends Record<string, SqlStorageValue> {
  id: string;
  api_key: string;
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
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);

    // Get the main task manager DO
    const taskManagerId = env.TASK_MANAGER.idFromName("main");
    const taskManager = env.TASK_MANAGER.get(taskManagerId);

    if (url.pathname === "/api/tasks" && request.method === "POST") {
      return taskManager.createTask(await request.json());
    }

    if (url.pathname === "/api/tasks" && request.method === "GET") {
      return taskManager.getTasks();
    }

    if (url.pathname.startsWith("/task/")) {
      const taskId = url.pathname.split("/")[2];
      return taskManager.getTaskDetails(taskId);
    }

    return new Response("Not found", { status: 404 });
  },
};

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
        api_key TEXT NOT NULL,
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
        keywords TEXT
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
  }

  async createTask(taskData: TaskData): Promise<Response> {
    const taskId = crypto.randomUUID();
    const now = Date.now();
    console.log({ taskData });

    // Store task in database
    this.sql.exec(
      `INSERT INTO tasks (id, api_key, processor, input, task_spec, created_at) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      taskId,
      taskData.apiKey,
      taskData.processor,
      taskData.input,
      taskData.taskSpec ? JSON.stringify(taskData.taskSpec) : null,
      now
    );

    // Create a task runner DO for this specific task
    const taskRunnerId = this.env.TASK_RUNNER.idFromName(taskId);
    const taskRunner = this.env.TASK_RUNNER.get(taskRunnerId);

    // Start the task runner (fire and forget)
    taskRunner.runTask(taskId, taskData);

    return new Response(JSON.stringify({ taskId, status: "started" }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  async getTasks(): Promise<Response> {
    const result = this.sql.exec(`
      SELECT id, processor, status, created_at, completed_at, title, slug, keywords,
             substr(input, 1, 100) as input_preview
      FROM tasks 
      ORDER BY created_at DESC
    `);

    const tasks = result.toArray().map((row: any) => ({
      id: row.id,
      processor: row.processor,
      status: row.status,
      title: row.title,
      slug: row.slug,
      keywords: row.keywords,
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

  async getTaskDetails(taskId: string): Promise<Response> {
    // Get task info
    const taskResult = this.sql.exec<TaskRow>(
      `SELECT * FROM tasks WHERE id = ?`,
      taskId
    );
    const taskRows = taskResult.toArray() as TaskRow[];

    if (taskRows.length === 0) {
      return new Response("Task not found", { status: 404 });
    }

    const task = taskRows[0];

    // Get all events for this task
    const eventsResult = this.sql.exec<EventRow>(
      `
      SELECT event_type, event_data, timestamp 
      FROM task_events 
      WHERE task_id = ? 
      ORDER BY timestamp ASC
    `,
      taskId
    );

    const events = eventsResult.toArray();

    const stuff = events.map((row: EventRow) => ({
      event_type: row.event_type as string,
      event_data: JSON.parse(row.event_data) as any,
      timestamp: new Date(row.timestamp).valueOf(),
    }));

    const response = {
      task: {
        id: task.id,
        processor: task.processor,
        input: task.input,
        taskSpec: task.task_spec ? JSON.parse(task.task_spec) : null,
        runId: task.run_id,
        status: task.status,
        title: task.title,
        slug: task.slug,
        keywords: task.keywords,
        confidence: task.confidence,
        createdAt: new Date(task.created_at).toISOString(),
        completedAt: task.completed_at
          ? new Date(task.completed_at).toISOString()
          : null,
        result: task.result ? JSON.parse(task.result) : null,
        resultContent: task.result_content,
      },
      events,
    };

    return new Response(JSON.stringify(response, null, 2), {
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
      `UPDATE tasks SET title = ?, slug = ?, keywords = ? WHERE id = ?`,
      metadata.title,
      metadata.slug,
      metadata.keywords,
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

      if (count === 0) {
        return slug;
      }

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
            messages: [
              {
                role: "user",
                content: prompt,
              },
            ],
            max_tokens: 500,
            temperature: 0.7,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(`Groq API error: ${response.status}`);
      }

      const data = response.json() as Promise<GroqResponse>;
      const content = (await data).choices[0]?.message?.content;

      if (!content) {
        throw new Error("No content in Groq response");
      }

      const metadata = JSON.parse(content) as {
        title: string;
        keywords: string;
      };
      const baseSlug = this.slugify(metadata.title);
      const slug = await this.generateSlug(baseSlug);

      await this.updateTaskMetadata(taskId, {
        title: metadata.title,
        slug,
        keywords: metadata.keywords,
      });

      await this.addEvent(taskId, "metadata_generated", {
        title: metadata.title,
        slug,
        keywords: metadata.keywords,
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

  async runTask(taskId: string, taskData: TaskData): Promise<void> {
    try {
      // Get the main task manager to report back to
      const taskManagerId = this.env.TASK_MANAGER.idFromName("main");
      const taskManager = this.env.TASK_MANAGER.get(taskManagerId);

      // Create the task run
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
            "x-api-key": taskData.apiKey,
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
            "x-api-key": taskData.apiKey,
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
            // Stream ended, check final status
            await this.checkFinalStatus(
              taskId,
              runId,
              taskData.apiKey,
              taskManager
            );
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

                // Check if it's a status event indicating completion
                if (eventData.type === "status") {
                  if (eventData.status === "completed") {
                    // Get the final result
                    await this.fetchAndStoreResult(
                      taskId,
                      runId,
                      taskData.apiKey,
                      taskData.input,
                      taskManager
                    );
                    return; // Exit the function
                  } else if (eventData.status === "failed") {
                    await taskManager.updateTaskStatus(taskId, "failed");
                    return; // Exit the function
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
          headers: {
            "x-api-key": apiKey,
          },
        }
      );

      if (resultResponse.ok) {
        const result = (await resultResponse.json()) as TaskRunResult;

        // Extract content and confidence
        const resultContent = result.output.content;
        const confidence = this.extractConfidence(result.output.basis);

        // Update task with result and extracted data
        await taskManager.updateTaskResult(
          taskId,
          result,
          resultContent,
          confidence
        );
        await taskManager.addEvent(taskId, "result", result);
        await taskManager.updateTaskStatus(taskId, "completed", result);

        // Generate metadata asynchronously
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
      // Stream ended without completion status, check current status
      const statusResponse = await fetch(
        `https://api.parallel.ai/v1/tasks/runs/${runId}`,
        {
          headers: {
            "x-api-key": apiKey,
          },
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
          // Still running or other status
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
    // Extract confidence from basis array, prioritizing the most confident level
    const confidenceLevels = basis
      .map((b) => b.confidence)
      .filter((c): c is string => c !== undefined && c !== null);

    if (confidenceLevels.length === 0) {
      return "unknown";
    }

    // Priority: high > medium > low > unknown
    if (confidenceLevels.includes("low")) return "low";
    if (confidenceLevels.includes("medium")) return "medium";
    if (confidenceLevels.includes("high")) return "high";

    return confidenceLevels[0] || "unknown";
  }
}
