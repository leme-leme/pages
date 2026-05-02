// Analytics Engine column mapping. AE uses positional `blob1..blob20` and
// `double1..double20` columns, plus `indexes` (sampled). We index by event
// type so we can `WHERE index1 = 'media.upload'` cheaply.
//
// Keep additions APPEND-ONLY: changing a column's meaning later silently
// poisons historical rows.

export const ColumnMappings = {
  // blobs (strings, max 20)
  eventType: "blob1",       // duplicate of index1, useful for SELECT
  owner: "blob2",
  repo: "blob3",
  branch: "blob4",
  actorType: "blob5",       // user | api_token | system
  actorUserId: "blob6",
  actorEmail: "blob7",
  resourceType: "blob8",    // collection | file | media | collaborator | api-token | storage-config | error | web-vital
  resourceId: "blob9",
  // event-specific:
  status: "blob10",         // for cms.error: HTTP status; for media.upload: provider
  route: "blob11",          // for errors: request path; for web-vitals: page path
  metric: "blob12",         // for web-vitals: LCP/INP/CLS/FCP/TTFB
  navigationType: "blob13", // for web-vitals: navigate/reload/back-forward
  userAgent: "blob14",
  country: "blob15",
  errorMessage: "blob16",   // truncated to 256 chars
  // free-form
  extra: "blob17",          // JSON string for anything else, capped

  // doubles (numbers, max 20)
  count: "double1",         // always 1, lets us SUM(double1) for event counts
  bytes: "double2",         // upload bytes / egress bytes
  durationMs: "double3",    // for errors / queries
  numericValue: "double4",  // web-vital value
} as const;

export type EventType =
  | "cms.entry.create" | "cms.entry.update" | "cms.entry.delete"
  | "cms.media.upload" | "cms.media.delete"
  | "cms.media.egress"  // egress bytes per /api/s3 hit
  | "cms.collaborator.invite" | "cms.collaborator.remove" | "cms.collaborator.update-role" | "cms.collaborator.update-grants"
  | "cms.api-token.create" | "cms.api-token.revoke"
  | "cms.storage-config.update" | "cms.storage-config.delete"
  | "cms.session.start"
  | "cms.error"
  | "cms.web-vital";

export type AnalyticsEvent = {
  type: EventType;
  owner?: string | null;
  repo?: string | null;
  branch?: string | null;
  actor?: {
    type?: "user" | "api_token" | "system";
    userId?: string | null;
    email?: string | null;
  };
  resourceType?: string | null;
  resourceId?: string | null;
  // event-specific:
  status?: string | null;
  route?: string | null;
  metric?: string | null;
  navigationType?: string | null;
  userAgent?: string | null;
  country?: string | null;
  errorMessage?: string | null;
  bytes?: number | null;
  durationMs?: number | null;
  numericValue?: number | null;
  extra?: Record<string, unknown> | null;
};
