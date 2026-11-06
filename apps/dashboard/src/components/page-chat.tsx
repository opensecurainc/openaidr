"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  LoaderCircle,
  RotateCcw,
  Send,
  Sparkles,
  Square,
  UserRound,
  X,
} from "lucide-react";
import { ChatMarkdown } from "@/components/chat-markdown";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { APIError } from "@/lib/api";
import { streamChat } from "@/lib/page-chat";
import { capturePageContext } from "@/lib/page-context";
import { cn } from "@/lib/utils";

type Message = { role: "user" | "assistant"; content: string };
const SUGGESTED_QUESTIONS = [
  "Summarize this page",
  "What needs my attention?",
  "Explain the key numbers",
];

function MessageRole({ role }: { role: Message["role"] }) {
  return (
    <Badge variant={role === "user" ? "outline" : "default"}>
      {role === "user" ? (
        <UserRound aria-hidden="true" />
      ) : (
        <Sparkles aria-hidden="true" />
      )}
      {role === "user" ? "You" : "OpenAIDR Assistant"}
    </Badge>
  );
}

function ChatMessage({ role, content }: Message) {
  return (
    <div
      className={cn(
        "flex flex-col gap-2",
        role === "user" ? "items-end" : "items-start",
      )}
    >
      <MessageRole role={role} />
      <div
        className={cn(
          "min-w-0 max-w-[90%] break-words rounded-lg px-3 py-2 text-foreground",
          role === "user" ? "border border-border bg-card" : "bg-muted",
        )}
      >
        {role === "user" ? (
          <p className="whitespace-pre-wrap">{content}</p>
        ) : (
          <ChatMarkdown content={content} />
        )}
      </div>
    </div>
  );
}

export function PageChat({ path, title }: { path: string; title: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [pending, setPending] = useState("");
  const [reply, setReply] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const active = useRef<AbortController | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const log = useRef<HTMLDivElement>(null);

  useEffect(
    () => () => {
      active.current?.abort();
      active.current = null;
    },
    [],
  );
  useEffect(() => {
    if (open && !pending) input.current?.focus();
  }, [open, pending]);
  useEffect(() => {
    if (log.current) log.current.scrollTop = log.current.scrollHeight;
  }, [messages, pending, reply, open]);

  function cancel() {
    active.current?.abort();
    active.current = null;
    if (pending) setQuestion(pending);
    setPending("");
    setReply("");
  }

  function close() {
    cancel();
    setOpen(false);
    trigger.current?.focus();
  }

  function reset() {
    cancel();
    setQuestion("");
    setMessages([]);
    setError("");
    setNotice("");
    input.current?.focus();
  }

  async function send(text: string) {
    const content = text.trim();
    if (!content || active.current) return;
    setError("");
    let page;
    try {
      page = capturePageContext(path, title);
    } catch (error) {
      setQuestion(content);
      setError(
        error instanceof Error ? error.message : "Cannot read this page.",
      );
      return;
    }
    let history = messages.slice(-8);
    while (
      history.reduce((sum, item) => sum + item.content.length, content.length) >
      24_000
    ) {
      history = history.slice(2);
    }
    const outgoing: Message[] = [...history, { role: "user", content }];
    setMessages(history);
    setNotice(
      page.truncated
        ? "This page is long. Only its first 20,000 characters are shared."
        : "",
    );
    const controller = new AbortController();
    active.current = controller;
    setPending(content);
    setReply("");
    setQuestion("");
    const timeout = setTimeout(() => controller.abort(), 55_000);
    try {
      const answer = await streamChat(
        JSON.stringify({ page, messages: outgoing }),
        controller.signal,
        (text) => {
          if (!controller.signal.aborted && active.current === controller) {
            setReply(text);
          }
        },
      );
      if (controller.signal.aborted || active.current !== controller) return;
      setMessages([...outgoing, { role: "assistant", content: answer }]);
    } catch (error) {
      if (active.current !== controller) return;
      if (error instanceof APIError && error.status === 401) {
        setMessages([]);
        router.replace("/login");
      } else {
        setError(
          controller.signal.aborted
            ? "OpenAIDR Assistant took too long. Please try again."
            : error instanceof Error
              ? error.message
              : "OpenAIDR Assistant failed. Please try again.",
        );
        setQuestion(content);
      }
    } finally {
      clearTimeout(timeout);
      if (active.current === controller) {
        active.current = null;
        setPending("");
        input.current?.focus();
      }
    }
  }

  return (
    <>
      <Button
        ref={trigger}
        variant="assistant"
        size="header-icon"
        aria-label="Ask about this page"
        title="Ask about this page"
        aria-expanded={open}
        aria-controls="page-chat"
        onClick={() => (open ? close() : setOpen(true))}
      >
        <Sparkles aria-hidden="true" className="size-5" />
      </Button>
      {open && (
        <aside
          id="page-chat"
          aria-labelledby="page-chat-title"
          data-page-chat-exclude
          className="fixed bottom-4 right-4 z-40 flex h-[min(640px,calc(100dvh-5rem))] w-[min(26rem,calc(100vw-2rem))] flex-col rounded-lg border bg-card text-sm shadow-overlay"
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              event.stopPropagation();
              close();
            }
          }}
        >
          <div className="flex items-start justify-between gap-3 border-b px-4 py-3">
            <div className="min-w-0">
              <h2 id="page-chat-title" className="text-base font-semibold">
                OpenAIDR Assistant
              </h2>
              <p className="mt-1 text-xs text-muted-foreground">
                Current page: {title}
              </p>
            </div>
            <div className="flex gap-1">
              <Button
                variant="ghost"
                size="icon"
                aria-label="New chat"
                onClick={reset}
              >
                <RotateCcw aria-hidden="true" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Close OpenAIDR Assistant"
                onClick={close}
              >
                <X aria-hidden="true" />
              </Button>
            </div>
          </div>
          <div
            ref={log}
            role="log"
            aria-label="Chat messages"
            aria-live="polite"
            className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4"
          >
            {messages.length === 0 && !pending && (
              <div
                role="group"
                aria-label="Suggested questions"
                className="space-y-2"
              >
                {SUGGESTED_QUESTIONS.map((suggestion) => (
                  <Button
                    key={suggestion}
                    type="button"
                    variant="secondary"
                    className="w-full justify-start"
                    onClick={() => void send(suggestion)}
                  >
                    {suggestion}
                  </Button>
                ))}
              </div>
            )}
            {notice && (
              <p role="status" className="text-xs text-muted-foreground">
                {notice}
              </p>
            )}
            {messages.map((message, index) => (
              <ChatMessage key={index} {...message} />
            ))}
            {pending && (
              <>
                <ChatMessage role="user" content={pending} />
                {reply && <ChatMessage role="assistant" content={reply} />}
                <p
                  role="status"
                  className="flex items-center gap-2 text-muted-foreground"
                >
                  <LoaderCircle
                    aria-hidden="true"
                    className="size-4 animate-spin"
                  />{" "}
                  {reply ? "Responding…" : "Reading this page…"}
                </p>
              </>
            )}
            {error && (
              <p role="alert" className="text-destructive">
                {error}
              </p>
            )}
          </div>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void send(question);
            }}
            className="space-y-3 border-t p-4"
          >
            <label htmlFor="page-chat-question" className="sr-only">
              Your question
            </label>
            <div className="flex items-center gap-1 rounded-[1.5rem] border border-input bg-card p-1.5 focus-within:border-ring focus-within:ring-1 focus-within:ring-ring">
              <Textarea
                ref={input}
                id="page-chat-question"
                value={question}
                maxLength={4000}
                rows={1}
                className="field-sizing-content max-h-32 min-h-10 flex-1 resize-none rounded-none border-0 bg-transparent py-2.5 focus-visible:ring-0"
                disabled={Boolean(pending)}
                placeholder="Write a message…"
                onChange={(event) => setQuestion(event.target.value)}
                onKeyDown={(event) => {
                  if (
                    event.key === "Enter" &&
                    !event.shiftKey &&
                    !event.nativeEvent.isComposing
                  ) {
                    event.preventDefault();
                    event.currentTarget.form?.requestSubmit();
                  }
                }}
              />
              {pending ? (
                <Button
                  type="button"
                  variant="outline"
                  size="icon-lg"
                  className="rounded-full"
                  aria-label="Cancel"
                  title="Cancel"
                  onClick={(event) => {
                    // Send replaces this button before the click finishes.
                    event.preventDefault();
                    cancel();
                  }}
                >
                  <Square aria-hidden="true" />
                </Button>
              ) : (
                <Button
                  type="submit"
                  size="icon-lg"
                  className="rounded-full"
                  aria-label="Send"
                  title="Send"
                  disabled={!question.trim()}
                >
                  <Send aria-hidden="true" />
                </Button>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Questions and page text go to the OpenAIDR Intelligence service.
            </p>
          </form>
        </aside>
      )}
    </>
  );
}
