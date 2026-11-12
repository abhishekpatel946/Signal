export type Cve = { id: string; cvss: number; epss: number };

export type Evidence = {
  kind: string;
  detail: string;
  ip?: string | null;
  port?: number | null;
  product?: string | null;
  version?: string | null;
  country?: string | null;
};

export type Account = {
  domain: string;
  score: number;
  decision: "call_now" | "watch" | "low";
  why: string;
  fit: string;
  urgency: number;
  breakdown: Record<string, number>;
  reasons: string[];
  country: string | null;
  city: string | null;
  org_observed: string | null;
  n_hosts: number;
  n_ips: number;
  n_http: number;
  signals: {
    cve: boolean;
    exposure: boolean;
    eol: boolean;
    no_waf: boolean;
    self_signed: boolean;
    iot: boolean;
    waf_present: boolean;
    reachable: boolean;
  };
  cvss_max: number;
  epss_max: number;
  cves: Cve[];
  products: string[];
  dangerous: string[];
  security_contacts: string[];
  evidence: Evidence[];
  icp?: string;
};

export type Payload = {
  generated_from: string;
  stats: Record<string, number>;
  accounts: Account[];
};
