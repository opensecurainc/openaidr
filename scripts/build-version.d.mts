export function buildInfo(options?: { development?: boolean }): {
  version: string;
  source_commit: string;
  source_timestamp: number;
  built_at: string;
};
