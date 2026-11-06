// Shapes of the JSON the Rout panel API returns. They mirror the Go view structs in
// internal/rout/web_views.go and web_routes*.go; secrets are never part of them.

export type Level = 'info' | 'warn' | 'error'
export type RunState = 'running' | 'stopped' | 'disabled' | 'unmanaged' | 'unknown'

export interface SessionState {
  configured: boolean
  authenticated: boolean
  secure: boolean
  csrf?: string
  version?: string
  session_id?: string
  reauth_until?: string
}

export interface TrafficView {
  active: boolean
  up: number
  down: number
  total: number
  limit: number
  left: number
  next_reset?: string
  billing_day: number
  timezone?: string
  status: 'ok' | 'stopped_quota' | 'sealed' | 'paused' | 'manual'
  live: boolean
  incomplete?: boolean
}

export interface NodeView {
  id: string
  name: string
  kind: 'node' | 'relay'
  protocol: string
  label: string
  enabled: boolean
  state: RunState
  listen: string
  port: number
  public_host: string
  public_port: number
  networks: string[]
  inbound?: string
  family?: string
  sni?: string
  exit_id?: string
  exit_name?: string
  cert?: { days: number; self_signed: boolean }
  traffic?: TrafficView
  created_at?: string
  subscriptions: string[]
  warnings: string[]
  has_link: boolean
}

export interface RelayView extends NodeView {
  mode: 'local' | 'remote'
  target: string
  target_kind?: string
  transport: string
  outbound_policy?: string
  engine: string
  target_network?: string
  target_node?: string
  path: string[]
  /** Names of the relay-chain exits that dial through this relay. */
  chain_exits?: string[]
  /** True when one of those chain exits is the AI exit. */
  ai_chain?: boolean
}

export interface ProtocolInfo {
  id: string
  label: string
  networks: string[]
}
export interface ExitRef {
  id: string
  name: string
  kind: string
}
export interface HostInfo {
  ipv4: boolean
  ipv6: boolean
}

export interface NodeList {
  nodes: NodeView[]
  protocols: ProtocolInfo[]
  exits: ExitRef[]
  host: HostInfo
  monitoring: boolean
}

export interface RelayList {
  relays: RelayView[]
  nodes: ExitRef[]
  host: HostInfo
  exits: ExitRef[]
}

export interface ExitView {
  id: string
  name: string
  kind: 'classic' | 'remote' | 'chain'
  protocol: string
  label: string
  host: string
  port: number
  has_auth: boolean
  transport: string
  remote_network?: string
  nodes: string[]
  node_ids: string[]
  ai: boolean
  refs: number
  warning?: string
  via_relay?: string
  via_relay_name?: string
  via_address?: string
  /** Hop-by-hop route for display, e.g. ["Local inbound", "Relay CA-hop (TCP …)", "SOCKS5 …", "Internet"]. */
  path?: string[]
  ai_usable?: boolean
  ai_problem?: string
}

export interface DiagStep {
  layer: number
  layer_name: string
  level: 'info' | 'ok' | 'warn' | 'fail'
  text: string
}
export interface DiagResult {
  ok: boolean
  steps: DiagStep[]
}

export interface SubItemView {
  kind: 'local' | 'remote'
  node_id: string
  source_id?: string
  source?: string
  name: string
  custom_name?: string
  protocol?: string
  status: 'ok' | 'skipped'
  skipped?: string
  base64_ok: boolean
  base64_why?: string
  mihomo_ok: boolean
  mihomo_why?: string
  notes?: string[]
}

export interface PlanView {
  limit: number
  used: number
  left: number
  billing_day: number
  timezone?: string
  expires?: string
  next_reset?: string
  incomplete?: boolean
}

export interface SubscriptionView {
  id: string
  name: string
  enabled: boolean
  aggregate: boolean
  dedupe: boolean
  allow_insecure: boolean
  created_at: string
  items: SubItemView[]
  local_count: number
  remote_count: number
  plan?: PlanView
  can_reveal_url: boolean
}

export interface SubNodeChoice {
  id: string
  name: string
  protocol: string
  label: string
  kind: 'node' | 'relay'
  enabled: boolean
}

export interface SubscriptionList {
  subscriptions: SubscriptionView[]
  nodes: SubNodeChoice[]
  server?: { enabled: boolean; running: boolean; managed: boolean; public_url_set: boolean }
}

/** What the editor sends: the identity of every entry, in order. */
export interface SubItemInput {
  kind: 'local' | 'remote'
  node_id?: string
  source_id?: string
  remote_id?: string
  name?: string
}

export interface SourceStatus {
  state: 'never' | 'ok' | 'error'
  last_attempt?: string
  last_success?: string
  last_error?: string
  failures?: number
}

export interface SourceView {
  id: string
  name: string
  note?: string
  tags: string[]
  kind: 'url' | 'static'
  url_masked?: string
  user_agent?: string
  enabled: boolean
  interval_min: number
  created_at: string
  format?: string
  status: SourceStatus
  next_refresh?: string
  entries: number
  valid: number
  active: number
  errors: number
  skipped: number
  duplicates: number
  disabled: number
  user_info?: { upload: number; download: number; total: number; expire: number }
  title?: string
  refs: string[]
}

export interface SourceNode {
  id: string
  name: string
  protocol: string
  server: string
  port: number
  transport?: string
  security?: string
  sni?: string
  udp: boolean
  enabled: boolean
  link_ok: boolean
  link_issue?: string
  from_clash: boolean
  notes?: string[]
}

export interface SourceIssue {
  level: string
  line?: number
  name?: string
  protocol?: string
  reason: string
}

export interface RefreshResult {
  format: string
  valid: number
  errors: number
  skipped: number
  added: number
  removed: number
}

export interface SysPoint {
  at: number
  cpu: number
  mem_used: number
  net_rx_rate: number
  net_tx_rate: number
}

export interface SysInfo {
  cpu_percent: number
  cores: number
  load1: number
  mem_total: number
  mem_used: number
  swap_total: number
  swap_used: number
  disk_total: number
  disk_used: number
  net_rx_rate: number
  net_tx_rate: number
  net_rx_total: number
  net_tx_total: number
  uptime_sec: number
  hostname?: string
  history: SysPoint[] | null
}

export interface PublicIPs {
  ipv4: string
  ipv6: string
  checked_at?: string
  checking: boolean
  local_ipv4: boolean
  local_ipv6: boolean
}

export interface Alert {
  level: Level
  code: string
  subject?: string
  detail?: string
  link?: string
}

export interface CountSet {
  total: number
  running: number
  stopped: number
  disabled: number
}

export interface UpdateInfo {
  current: string
  latest?: string
  available: boolean
  checked_at?: string
  error?: string
}

export interface Overview {
  version: string
  system: SysInfo
  network: PublicIPs
  counts: {
    nodes: CountSet
    relays: CountSet
    exits: number
    subscriptions: number
    aggregates: number
    sources: number
    sources_ok: number
    sources_failed: number
    remote_nodes: number
  }
  traffic: {
    monitoring: boolean
    up: number
    down: number
    total: number
    top: { id: string; name: string; up: number; down: number; total: number }[]
  }
  certs: { id: string; name: string; days: number; self_signed: boolean }[]
  quotas: { kind: 'node' | 'subscription'; id: string; name: string; used: number; limit: number; left: number; next_reset?: string }[]
  alerts: Alert[]
  subscription_server: { enabled: boolean; running: boolean; managed: boolean }
  update: UpdateInfo
}

export interface ServiceItem {
  unit: string
  kind: 'subscription' | 'web' | 'node' | 'relay'
  name: string
  state: string
}

export interface PermissionCheck {
  path: string
  mode: string
  expected: string
  ok: boolean
}

export interface SystemView {
  version: string
  update: UpdateInfo
  runtime: { os: string; arch: string; go: string; init: string }
  system: SysInfo
  services: ServiceItem[]
  web: {
    port: number
    allowed_hosts: string[]
    session_idle_min: number
    session_max_hours: number
    secure_cookie: boolean
    https_domain?: string
    password_set: boolean
    password_changed_at?: string
    secure_request: boolean
  }
  subscription: {
    enabled: boolean
    running: boolean
    managed: boolean
    port: number
    public_url?: string
    mihomo_test_url?: string
  }
  permissions: PermissionCheck[]
}

export interface NetworkView {
  public_ips: PublicIPs
  dns: { servers: string[]; ok: boolean; millis: number; error?: string }
}

export interface HTTPSView {
  domain: string
  installed: boolean
  running: boolean
  local_running: boolean
  route_found: boolean
  route_ok: boolean
  route_conflict: boolean
  ownership?: string
  renewal?: string
  last_error?: string
  dns: { a: string[]; aaaa: string[]; matched: boolean; proxied: boolean; uncertain: boolean }
  verification: {
    local_service: boolean
    local_tls: boolean
    public_from_host: boolean
    external: boolean
    certificate_error: boolean
    expires?: string
    error?: string
  }
  issues: string[]
}

export interface SessionInfo {
  id: string
  created_at: string
  last_seen: string
  ip: string
  agent: string
  current: boolean
}

export interface ActivityEntry {
  at: string
  ip: string
  action: string
}

export interface DiffSet {
  now: number
  backup: number
  removed: string[]
  added: string[]
}
export interface RestorePlan {
  full: boolean
  created_at?: string
  rout_version?: string
  nodes: DiffSet
  relays: DiffSet
  exits: DiffSet
  subscriptions: DiffSet
  sources: DiffSet
  warnings: string[]
}

// ---- AI smart routing ------------------------------------------------------------------

export interface AINode {
  id: string
  name: string
  protocol: string
  bound: boolean
  eligible: boolean
  /** Service state, already worded in the interface language by the server. */
  running: string
  in_sync: boolean
  note?: string
  /** The node's ordinary route: an exit name or "direct". */
  exit: string
}

export interface AIService {
  name: string
  suffixes: string[]
}

export interface AIView {
  enabled: boolean
  rule_set: number
  rule_set_available: number
  exit_id?: string
  exit?: ExitView
  problems: string[]
  nodes: AINode[]
  exits: ExitView[]
  relays: RelayView[]
  services: AIService[]
  limits: string[]
}

export type AIRoute = 'ai' | 'original' | 'blocked'
export interface AISimulation {
  host: string
  nodes: { id: string; name: string; route: AIRoute }[]
}

export type ChainProtocol = 'socks5' | 'http' | 'https' | 'node'
export interface ChainSpec {
  name?: string
  via_relay?: string
  via_address?: string
  protocol: ChainProtocol
  host?: string
  port?: number
  username?: string
  password?: string
  link?: string
}

// ---- panel HTTPS -----------------------------------------------------------------------

export type CheckLevel = 'ok' | 'warn' | 'fail' | 'info'

export interface PanelHTTPSReport {
  domain: string
  ownership: 'none' | 'managed' | 'external' | 'modified' | string
  pending: boolean
  last_error?: string
  network: { ipv4?: string; ipv6?: string; ipv4_nat: boolean; ipv6_nat: boolean; ipv6_only: boolean }
  records?: string[]
  verification: {
    local_service: boolean
    host_allowed: boolean
    local_tls: boolean
    public_https: boolean
    login_page: boolean
    certificate_error: boolean
    expires?: string
    issuer?: string
  }
  checks: { key: string; level: CheckLevel; text: string }[]
  url?: string
}

export interface PanelRepairResult {
  ok: boolean
  pending: boolean
  diagnosis: string
}

// ---- Telegram Bot remote management -----------------------------------------------------
// The bot token is write-only: no call ever returns it.

export type TelegramRole = 'hub' | 'agent'
export type TelegramConnState = 'unbound' | 'starting' | 'connected' | 'connecting' | 'pending' | 'revoked' | 'error' | 'stopped'

export interface TelegramServer {
  id: string
  name: string
  self: boolean
  online: boolean
  last_seen?: string
  fingerprint: string
  version?: string
  ai_enabled?: boolean
  exit_name?: string
}

export interface TelegramPending {
  id: string
  name: string
  fingerprint: string
  requested_at: string
}

export interface TelegramStatus {
  bound: boolean
  role?: TelegramRole
  server_id?: string
  server_name?: string
  bot_username?: string
  chat_id_masked?: string
  fingerprint?: string
  service: { installed: boolean; running: boolean; managed: boolean }
  connection: { state: TelegramConnState; detail?: string; last_ok?: string }
  hub?: { endpoints: string[]; fingerprint: string; multi_server: boolean; port: number }
  follows?: { endpoints: string[]; fingerprint: string }
  servers: TelegramServer[]
  pending: TelegramPending[]
  audit: string[]
}

export interface TelegramProbe {
  bot_username: string
  suggested_name: string
  webhook_active: boolean
  hub: { found: false } | { found: true; endpoints: string[]; fingerprint: string; hub_name?: string }
}

export interface TelegramBindRequest {
  token: string
  chat_id: string
  server_name?: string
  role: TelegramRole
  /** Required for an agent: must equal the fingerprint the probe reported for the hub. */
  trust_hub_fp?: string
  multi_server?: boolean
  delete_webhook?: boolean
}

export interface TelegramPatch {
  server_name?: string
  token?: string
  chat_id?: string
  multi_server?: boolean
}

export interface TelegramTestResult {
  ok: boolean
  steps: { level: CheckLevel; text: string }[]
}
