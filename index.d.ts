export interface LeakFinding {
  id: string;
  category: 'dns' | 'webrtc' | 'lan' | 'http' | 'fingerprint';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  leakedData?: string | string[];
  remediation: string;
}

export interface AuditReport {
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  timestamp: string;
  summary: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    passedCount: number;
  };
  findings: LeakFinding[];
  dns: {
    resolvers: string[];
    isEncrypted: boolean;
    provider: string;
    hasSplitDnsLeak: boolean;
  };
  lan: {
    exposedServices: Array<{ port: number; host: string; service: string; severity: string }>;
    interfacesCount: number;
  };
  webrtc: {
    leaksDetected: boolean;
    candidatesCount: number;
    exposedIps: string[];
  };
  http: {
    headerLeaks: string[];
    clientHintsExposed: boolean;
  };
}

export declare function runFullAudit(options?: { mock?: boolean; customHeaders?: Record<string, string> }): Promise<AuditReport>;
export declare function auditDns(options?: { mockServers?: string[] }): Promise<{ findings: LeakFinding[]; dnsDetails: any }>;
export declare function auditLanExposures(options?: { mockBindings?: Array<{ port: number; host: string; service: string }> }): Promise<{ findings: LeakFinding[]; lanDetails: any }>;
export declare function auditWebRtcCandidates(candidates: string[]): { findings: LeakFinding[]; webrtcDetails: any };
export declare function calculatePrivacyScore(findings: LeakFinding[]): { score: number; grade: string; summary: any };
