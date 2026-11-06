import {
  Activity,
  Archive,
  BookOpen,
  CircleDollarSign,
  ClipboardList,
  Cable,
  Cpu,
  FileSearch,
  Gauge,
  History,
  LayoutDashboard,
  Monitor,
  PackageSearch,
  PlusCircle,
  Radio,
  ScanSearch,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  UserRoundSearch,
  Users,
  type LucideIcon,
} from "lucide-react";

export type NavigationPage = {
  path: string;
  title: string;
  navTitle?: string;
  description: string;
  icon: LucideIcon;
  /** Show the telemetry range and service filters, refresh, and status. */
  telemetryFilters?: boolean;
  /**
   * Show only the telemetry connection status and failure notice: for pages
   * that read telemetry (such as device status) without filtering it.
   */
  telemetryStatus?: boolean;
};

export type NavigationGroup = {
  title: string;
  pages: readonly NavigationPage[];
};

/** Shared source of truth for desktop/mobile navigation and page headings. */
export const navigation = [
  {
    title: "Overview",
    pages: [
      {
        path: "/",
        title: "Overview",
        description:
          "AI activity, risk, and coverage in one place.",
        icon: LayoutDashboard,
      },
    ],
  },
  {
    title: "AI Asset Management",
    pages: [
      {
        path: "/ai-inventory",
        title: "AI Apps",
        description:
          "Review applications discovered on your endpoints.",
        icon: Cpu,
      },
      {
        path: "/ai-supply-chain",
        title: "AI Supply Chain",
        description:
          "Review reported packages, MCP servers, plugins, and scan coverage.",
        icon: PackageSearch,
      },
      {
        path: "/ai-skills",
        title: "AI Skills",
        description:
          "Review installed skills, scanner findings, and assessment coverage.",
        icon: BookOpen,
      },
    ],
  },
  {
    title: "Gateways",
    pages: [
      {
        path: "/gateways/overview",
        title: "Gateway Overview",
        navTitle: "Overview",
        description: "Connect gateways, manage instances, and review coverage and request health.",
        icon: LayoutDashboard,
      },
    ],
  },
  {
    title: "Detection and Response",
    pages: [
      {
        path: "/user-risk",
        title: "Risky Sessions/Users",
        description: "Review summaries, detection reports, and case outcomes.",
        icon: UserRoundSearch,
      },
      {
        path: "/detections",
        title: "Detection Queue",
        description: "Review investigation reports, detection coverage, and session eligibility.",
        icon: ClipboardList,
      },
      {
        path: "/evidence",
        title: "Evidence Search",
        description:
          "Find agent activity by user, device, and date.",
        icon: FileSearch,
      },
      {
        path: "/detection-rules",
        title: "Detection Rules",
        description: "Review configured detection rules and recent finding counts.",
        icon: ScanSearch,
      },
    ],
  },
  {
    title: "Real-time Guardrail",
    pages: [
      {
        path: "/guardrail/live",
        title: "Live Guardrail",
        description:
          "Inspect endpoint and gateway activity, policy decisions, and Guardrail assessments.",
        icon: Radio,
        telemetryStatus: true,
      },
      {
        path: "/guardrail/history",
        title: "Guardrail History",
        description:
          "Review endpoint and gateway checks, policy decisions, latency, and reported outcomes.",
        icon: History,
      },
      {
        path: "/guardrail/configuration",
        title: "Guardrail Configuration",
        description:
          "Manage the saved hook mode and review the backend policy rules.",
        icon: SlidersHorizontal,
      },
      {
        path: "/company-knowledge",
        title: "Company Policy and Knowledge",
        description:
          "Tell Guardrail what to protect and give it the context to assess agent activity.",
        icon: BookOpen,
      },
    ],
  },
  {
    title: "Cost Management",
    pages: [
      {
        path: "/costs/agents",
        title: "AI Agent Costs",
        description: "Track AI spend over time and by user, model, project, activity, and reasoning effort.",
        icon: CircleDollarSign,
      },
      {
        path: "/costs/openaidr",
        title: "Credits & Usage",
        description:
          "Track your credit balance and usage by feature.",
        icon: Gauge,
      },
    ],
  },
  {
    title: "Administration",
    pages: [
      {
        path: "/administration/app",
        title: "App Health",
        description:
          "Review app connectivity, health, and telemetry across enrolled devices.",
        icon: Monitor,
        telemetryFilters: true,
      },
      {
        path: "/administration/server",
        title: "Server Health",
        description: "Review backend service status and processing health.",
        icon: Activity,
      },
      {
        path: "/administration/enrollment",
        title: "App Enrollment",
        description: "Create and manage enrollment tokens to connect devices to OpenAIDR.",
        icon: PlusCircle,
      },
      {
        path: "/administration/integrations",
        title: "Integrations",
        description: "Connect services to deliver alerts and reports to your team.",
        icon: Cable,
      },
      {
        path: "/audit-logs",
        title: "Audit Logs",
        description: "Review administrative changes and recorded user actions.",
        icon: Archive,
      },
      {
        path: "/administration/users",
        title: "Users and Roles",
        description: "Review organization members, roles, and account status.",
        icon: Users,
      },
      {
        path: "/administration/settings",
        title: "Settings",
        description: "Review organization settings and telemetry retention.",
        icon: Settings,
      },
    ],
  },
] as const satisfies readonly NavigationGroup[];

export type PagePath = (typeof navigation)[number]["pages"][number]["path"];

export function findNavigationPage(pathname: string):
  | {
      group: string;
      page: NavigationPage;
    }
  | undefined {
  const path = pathname.replace(/\/$/, "") || "/";
  if (/^\/gateways\/instances\/[^/]+$/.test(path)) {
    return { group: "Gateways", page: {
      path, title: "Gateway Instance", description: "Review reported coverage, configuration, and connection setup.", icon: Cable,
    } };
  }
  if (/^\/gateways\/requests\/[^/]+$/.test(path)) {
    return { group: "Gateways", page: {
      path, title: "Gateway Request", description: "Review the evaluated decision, returned decision, and reported outcome.", icon: FileSearch,
    } };
  }
  if (path === "/security-posture") {
    return {
      group: "Detection and Response",
      page: {
        path,
        title: "Security Posture",
        description: "Review prevention policy and security coverage limitations.",
        icon: ShieldCheck,
      },
    };
  }
  if (path === "/detections/preview") {
    return {
      group: "Detection and Response",
      page: {
        path,
        title: "Detection Queue preview",
        description: "Proposed Detection Queue layout with illustrative sample data.",
        icon: ClipboardList,
      },
    };
  }
  if (path === "/ai-skills/preview") {
    return {
      group: "AI Asset Management",
      page: {
        path,
        title: "AI Skills preview",
        description: "Proposed AI Skills layout with illustrative sample data.",
        icon: BookOpen,
      },
    };
  }
  if (path === "/company-knowledge/preview/policy") {
    return {
      group: "Real-time Guardrail",
      page: {
        path,
        title: "Company Policy preview",
        description: "Proposed Company Policy layout with illustrative sample data.",
        icon: BookOpen,
      },
    };
  }
  if (path === "/company-knowledge/preview/guardrails") {
    return {
      group: "Real-time Guardrail",
      page: {
        path,
        title: "Guardrail Configuration preview",
        description: "Proposed Guardrail Configuration layout with illustrative sample data.",
        icon: BookOpen,
      },
    };
  }
  if (path === "/user-risk/findings") {
    return {
      group: "Detection and Response",
      page: {
        path,
        title: "User findings",
        description: "Investigate reported user activity across incident reports and policy findings.",
        icon: UserRoundSearch,
      },
    };
  }
  if (/^\/detections\/reports\/[0-9a-f-]+$/i.test(path)) {
    return { group: "Detection and Response", page: {
      path, title: "Investigation report", description: "Review the conclusion, evidence, scope, and recommended response.", icon: FileSearch,
    } };
  }
  // Detail routes use shared shell metadata without adding a session-index link.
  if (/^\/sessions\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(path)) {
    return {
      group: "Detection and Response",
      page: {
        path,
        title: "Session",
        description: "Review stored risk, policy decisions, and retained investigation evidence.",
        icon: FileSearch,
      },
    };
  }
  for (const group of navigation) {
    const page = group.pages.find(
      (candidate) =>
        path === candidate.path ||
        (candidate.path !== "/" && path.startsWith(`${candidate.path}/`)),
    );
    if (page) return { group: group.title, page };
  }
}
