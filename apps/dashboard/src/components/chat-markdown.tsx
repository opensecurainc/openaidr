import { memo, type ReactNode } from "react";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { CodeBlock, InlineCode } from "@/components/ui/code-block";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

function Heading({ children }: { children?: ReactNode }) {
  return <h3 className="font-semibold">{children}</h3>;
}

const components: Components = {
  h1: Heading,
  h2: Heading,
  h3: Heading,
  h4: Heading,
  h5: Heading,
  h6: Heading,
  p: ({ children }) => <p className="whitespace-pre-wrap">{children}</p>,
  strong: ({ children }) => <strong className="font-semibold">{children}</strong>,
  ul: ({ children }) => <ul className="list-disc space-y-1 pl-5">{children}</ul>,
  ol: ({ children, start }) => (
    <ol start={start} className="list-decimal space-y-1 pl-5">
      {children}
    </ol>
  ),
  li: ({ children }) => <li className="space-y-1">{children}</li>,
  blockquote: ({ children }) => (
    <blockquote className="space-y-2 border-l-2 border-input pl-3">
      {children}
    </blockquote>
  ),
  code: ({ children }) => <InlineCode>{children}</InlineCode>,
  pre: ({ children }) => (
    <CodeBlock
      tabIndex={0}
      className="whitespace-pre break-normal focus-visible:outline-2 focus-visible:outline-ring [&_code]:rounded-none [&_code]:bg-transparent [&_code]:p-0"
    >
      {children}
    </CodeBlock>
  ),
  table: ({ children }) => (
    <div
      role="region"
      aria-label="Table in assistant reply"
      tabIndex={0}
      className="max-w-full overflow-x-auto focus-visible:outline-2 focus-visible:outline-ring [&_[data-slot=table-container]]:overflow-visible"
    >
      <Table>{children}</Table>
    </div>
  ),
  thead: ({ children }) => <TableHeader>{children}</TableHeader>,
  tbody: ({ children }) => <TableBody>{children}</TableBody>,
  tr: ({ children }) => <TableRow>{children}</TableRow>,
  th: ({ children, style }) => <TableHead style={style}>{children}</TableHead>,
  td: ({ children, style }) => <TableCell style={style}>{children}</TableCell>,
  // Never fetch images or render active HTML from a model response.
  img: ({ alt }) => <span>{alt}</span>,
  a: ({ children, href }) =>
    href && /^https?:\/\//i.test(href) ? (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="text-primary underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-ring"
      >
        {children}
      </a>
    ) : (
      <span>{children}</span>
    ),
};

export const ChatMarkdown = memo(function ChatMarkdown({
  content,
}: {
  content: string;
}) {
  return (
    <div className="space-y-2 text-sm [overflow-wrap:anywhere] [&_pre]:[overflow-wrap:normal]">
      <Markdown remarkPlugins={[remarkGfm]} components={components}>
        {content}
      </Markdown>
    </div>
  );
});
