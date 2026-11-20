# API Reference

Complete programmatic reference for the `leak-sentinel` core library.

## Module Exports

```typescript
import {
  runFullAudit,
  auditDns,
  auditWebRtcCandidates,
  auditLanExposures,
  auditHttpHeaders,
  auditFingerprintEntropy,
  calculatePrivacyScore,
  formatMarkdownReport,
  createAuditServer
} from 'leak-sentinel';
```

---

### `runFullAudit(options?: AuditOptions): Promise<AuditReport>`

Executes all five audit modules in sequence and computes the consolidated privacy health score and letter grade.

#### Parameters:
- `options.dnsOptions` *(Optional)*: Configuration object for DNS auditing (e.g. `mockServers: string[]`).
- `options.lanOptions` *(Optional)*: Configuration object for socket binding auditing (e.g. `mockBindings: Array<{ port: number, host: string, service?: string }>`).
- `options.webrtcCandidates` *(Optional)*: Array of SDP candidate strings to analyze.
- `options.customHeaders` *(Optional)*: Key-value dictionary of HTTP headers to evaluate.
- `options.fingerprintMetrics` *(Optional)*: Client device parameters including `webglRenderer`, `hasCanvasNoise`, and `fontsCount`.

#### Returns:
A `Promise` resolving to an `AuditReport` object.

---

### `auditDns(options?: DnsAuditOptions): Promise<{ findings: LeakFinding[], dnsDetails: DnsDetails }>`

Audits system-configured nameservers against known privacy criteria and checks for multi-homing split-tunnel leaks.

#### Returns:
- `findings`: Array of zero or more `LeakFinding` objects categorized as `dns`.
- `dnsDetails.resolvers`: Active IP addresses of resolvers queried.
- `dnsDetails.isEncrypted`: Boolean indicating whether exclusively privacy-grade encrypted resolvers are configured.
- `dnsDetails.hasSplitDnsLeak`: Boolean indicating concurrent local gateway and public nameserver configuration.

---

### `auditWebRtcCandidates(candidates: string[]): { findings: LeakFinding[], webrtcDetails: WebRtcDetails }`

Parses ICE candidate strings to classify connection pathways and detect public IP or IPv6 bypass disclosures.

#### Parameters:
- `candidates`: Array of raw SDP `candidate:...` strings.

#### Returns:
- `findings`: Array of findings (`WEBRTC_STUN_PUBLIC_IP_LEAK`, `WEBRTC_IPV6_BYPASS_LEAK`, `WEBRTC_INTERNAL_LAN_TOPOLOGY_LEAK`).
- `webrtcDetails.leaksDetected`: Boolean indicating presence of critical or high IP exposures.
- `webrtcDetails.exposedIps`: Array of unique IP addresses extracted from candidates.

---

### `auditLanExposures(options?: LanAuditOptions): Promise<{ findings: LeakFinding[], lanDetails: LanDetails }>`

Inspects network bindings on physical interfaces to detect sensitive services exposed to all network adapters (`0.0.0.0`).

#### Parameters:
- `options.mockBindings` *(Optional)*: Array of listener definitions for testing purposes.

#### Monitored Ports:
- `11434`: Ollama HTTP API (Critical)
- `2375`: Docker Daemon Plaintext Socket (Critical)
- `6379`: Redis In-Memory Store (High)
- `5432`, `3306`, `27017`: Relational and Document Databases (High)

---

### `calculatePrivacyScore(findings: LeakFinding[]): { score: number, grade: string, summary: ScoreSummary }`

Applies a deterministic scoring penalty model:
- Base score: `100`
- `CRITICAL` finding: `-25` points
- `HIGH` finding: `-15` points
- `MEDIUM` finding: `-8` points
- `LOW` finding: `-3` points

Score is clamped to `[0, 100]`. Grades assigned:
- `95 - 100`: `A+`
- `85 - 94`: `A`
- `75 - 84`: `B`
- `60 - 74`: `C`
- `45 - 59`: `D`
- `< 45`: `F`

---

### `formatMarkdownReport(report: AuditReport): string`

Serializes an `AuditReport` into a standardized GitHub Flavored Markdown document with summary tables, vulnerability descriptions, and mitigation commands.

---

### `createAuditServer(reportGetter: () => AuditReport, options?: ServerOptions): Promise<ServerInstance>`

Starts a local zero-dependency Node.js HTTP server delivering the audit dashboard and REST endpoints.

#### Parameters:
- `options.port`: Target port number (defaults to `8899`).
- `options.host`: Binding host (defaults strictly to `127.0.0.1`).
- `options.quiet`: Boolean suppressing terminal status logs.
- `options.openBrowser`: Boolean controlling automatic browser launch.
