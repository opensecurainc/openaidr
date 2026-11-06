import { apiResponse } from "@/lib/api";

const INCOMPLETE =
  "OpenAIDR Assistant returned an incomplete answer. Please try again.";

function answerText(value: unknown): string {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    Array.from(value).length > 8000
  ) {
    throw new Error(INCOMPLETE);
  }
  return value;
}

export async function streamChat(
  body: string,
  signal: AbortSignal,
  onText: (text: string) => void,
): Promise<string> {
  const response = await apiResponse("chat", {
    method: "POST",
    headers: { Accept: "text/event-stream" },
    body,
    signal,
  });
  const contentType = response.headers.get("Content-Type") || "";
  // A backend from before streaming was deployed still serves this contract.
  if (contentType.includes("application/json")) {
    return answerText((await response.json()).answer);
  }
  if (!contentType.includes("text/event-stream") || !response.body) {
    throw new Error(INCOMPLETE);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let text = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      buffer = (buffer + decoder.decode(value, { stream: !done })).replace(
        /\r\n/g,
        "\n",
      );
      if (buffer.length > 1 << 20) throw new Error(INCOMPLETE);
      let boundary;
      while ((boundary = buffer.indexOf("\n\n")) >= 0) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const data = frame
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trimStart())
          .join("\n");
        if (!data) continue;
        let event;
        try {
          event = JSON.parse(data);
        } catch {
          throw new Error(INCOMPLETE);
        }
        if (event?.type === "delta" && typeof event.text === "string") {
          text += event.text;
          if (Array.from(text).length > 8000) throw new Error(INCOMPLETE);
          onText(text);
        } else if (event?.type === "done") {
          return answerText(event.answer);
        } else if (event?.type === "error" && typeof event.message === "string") {
          throw new Error(event.message);
        } else {
          throw new Error(INCOMPLETE);
        }
      }
      if (done) throw new Error(INCOMPLETE);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
