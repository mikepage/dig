import { define } from "../../utils.ts";
import * as dnsPacket from "dns-packet";
import { Buffer } from "node:buffer";

type RecordType =
  | "A"
  | "AAAA"
  | "ANAME"
  | "CAA"
  | "CNAME"
  | "MX"
  | "NAPTR"
  | "NS"
  | "PTR"
  | "SOA"
  | "SRV"
  | "TXT";

interface GoogleDnsResponse {
  Status: number;
  AD?: boolean; // Authenticated Data - DNSSEC validation passed
  CD?: boolean; // Checking Disabled
  Answer?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
  Authority?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
}

interface DnssecInfo {
  validated: boolean;
  enabled: boolean;
}

const DNS_TYPE_MAP: Record<string, number> = {
  A: 1,
  AAAA: 28,
  CNAME: 5,
  MX: 15,
  NS: 2,
  TXT: 16,
  SOA: 6,
  PTR: 12,
};

interface DoHResult {
  records: unknown[];
  dnssec: DnssecInfo | null;
}

function parseDoHResponse(
  data: GoogleDnsResponse,
  type: RecordType,
  typeNum: number,
  dnssecValidate: boolean
): DoHResult {
  // DNSSEC info - AD (Authenticated Data) flag indicates validation passed
  const dnssec: DnssecInfo | null = dnssecValidate
    ? {
        validated: data.AD === true,
        enabled: true,
      }
    : null;

  if (!data.Answer) {
    return { records: [], dnssec };
  }

  // Filter answers to only include the requested type
  const answers = data.Answer.filter((a) => a.type === typeNum);

  // Parse the data based on record type
  const records = answers.map((answer) => {
    switch (type) {
      case "MX": {
        // MX format: "10 mail.example.com."
        const parts = answer.data.split(" ");
        return {
          preference: parseInt(parts[0], 10),
          exchange: parts.slice(1).join(" ").replace(/\.$/, ""),
        };
      }
      case "SOA": {
        // SOA format: "ns1.example.com. admin.example.com. 2024010101 3600 600 604800 60"
        const parts = answer.data.split(" ");
        return {
          mname: parts[0]?.replace(/\.$/, "") || "",
          rname: parts[1]?.replace(/\.$/, "") || "",
          serial: parseInt(parts[2], 10) || 0,
          refresh: parseInt(parts[3], 10) || 0,
          retry: parseInt(parts[4], 10) || 0,
          expire: parseInt(parts[5], 10) || 0,
          minimum: parseInt(parts[6], 10) || 0,
        };
      }
      case "TXT": {
        // TXT records come with quotes, remove them
        return [answer.data.replace(/^"|"$/g, "")];
      }
      case "CNAME":
      case "NS":
      case "PTR":
        // Remove trailing dot from domain names
        return answer.data.replace(/\.$/, "");
      default:
        return answer.data;
    }
  });

  return { records, dnssec };
}

async function resolveWithGoogleDoH(
  domain: string,
  type: RecordType,
  dnssecValidate: boolean = false
): Promise<DoHResult> {
  const typeNum = DNS_TYPE_MAP[type];
  // do=true requests DNSSEC data (sets DO bit), cd=true disables DNSSEC validation
  // When validation enabled: request DNSSEC data, allow validation to fail bad signatures
  // When validation disabled: use cd=true to skip validation (allows querying domains with broken DNSSEC)
  const params = new URLSearchParams({
    name: domain,
    type: typeNum.toString(),
  });
  if (dnssecValidate) {
    params.set("do", "true"); // Request DNSSEC data
  } else {
    params.set("cd", "true"); // Disable DNSSEC validation
  }
  const url = `https://dns.google/resolve?${params}`;

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Google DNS request failed: ${response.statusText}`);
  }

  const data: GoogleDnsResponse = await response.json();

  if (data.Status !== 0) {
    const statusMessages: Record<number, string> = {
      1: "Format error",
      2: "Server failure",
      3: "Non-existent domain",
      4: "Not implemented",
      5: "Query refused",
    };
    throw new Error(statusMessages[data.Status] || `DNS error: ${data.Status}`);
  }

  return parseDoHResponse(data, type, typeNum, dnssecValidate);
}

async function resolveWithCloudflareDoH(
  domain: string,
  type: RecordType,
  dnssecValidate: boolean = false,
  endpoint: string = "https://cloudflare-dns.com/dns-query",
  providerName: string = "Cloudflare"
): Promise<DoHResult> {
  const typeNum = DNS_TYPE_MAP[type];
  // Cloudflare DoH JSON API
  // cd=true disables DNSSEC validation
  const params = new URLSearchParams({
    name: domain,
    type: type,
  });
  if (dnssecValidate) {
    params.set("do", "true"); // Request DNSSEC data
  } else {
    params.set("cd", "true"); // Disable DNSSEC validation
  }
  const url = `${endpoint}?${params}`;

  const response = await fetch(url, {
    headers: {
      Accept: "application/dns-json",
    },
  });
  if (!response.ok) {
    throw new Error(`${providerName} DNS request failed: ${response.statusText}`);
  }

  const data: GoogleDnsResponse = await response.json();

  if (data.Status !== 0) {
    const statusMessages: Record<number, string> = {
      1: "Format error",
      2: "Server failure",
      3: "Non-existent domain",
      4: "Not implemented",
      5: "Query refused",
    };
    throw new Error(statusMessages[data.Status] || `DNS error: ${data.Status}`);
  }

  return parseDoHResponse(data, type, typeNum, dnssecValidate);
}

async function resolveWithCloudflareSecurityDoH(
  domain: string,
  type: RecordType,
  dnssecValidate: boolean = false
): Promise<DoHResult> {
  // Cloudflare Security DNS blocks malware and phishing domains
  return resolveWithCloudflareDoH(
    domain,
    type,
    dnssecValidate,
    "https://security.cloudflare-dns.com/dns-query"
  );
}

async function resolveWithCloudflareFamilyDoH(
  domain: string,
  type: RecordType,
  dnssecValidate: boolean = false
): Promise<DoHResult> {
  // Cloudflare Family DNS blocks malware, phishing, and adult content
  return resolveWithCloudflareDoH(
    domain,
    type,
    dnssecValidate,
    "https://family.cloudflare-dns.com/dns-query"
  );
}

// Binary DoH resolver using RFC 8484 wire format
async function resolveWithBinaryDoH(
  domain: string,
  type: RecordType,
  endpoint: string,
  providerName: string,
  dnssecValidate: boolean = false
): Promise<DoHResult> {
  const typeNum = DNS_TYPE_MAP[type];

  // Build DNS query packet - use type assertion for RecordType compatibility
  // deno-lint-ignore no-explicit-any
  const queryPacket: any = {
    type: "query",
    id: Math.floor(Math.random() * 65535),
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name: domain }],
  };

  // Add EDNS for DNSSEC support
  if (dnssecValidate) {
    queryPacket.additionals = [
      {
        type: "OPT",
        name: ".",
        udpPayloadSize: 4096,
        extendedRcode: 0,
        ednsVersion: 0,
        flags: dnsPacket.DNSSEC_OK,
        flag_do: true,
        options: [],
      },
    ];
  } else {
    // Set CD flag to disable DNSSEC validation
    queryPacket.flags = dnsPacket.RECURSION_DESIRED | dnsPacket.CHECKING_DISABLED;
  }

  // Encode query to binary wire format
  const queryBuffer = dnsPacket.encode(queryPacket);

  // Send POST request with binary DNS message
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/dns-message",
      Accept: "application/dns-message",
    },
    body: new Uint8Array(queryBuffer),
  });

  if (!response.ok) {
    throw new Error(`${providerName} DNS request failed: ${response.statusText}`);
  }

  // Decode binary response - use Buffer for dns-packet compatibility
  const responseArrayBuffer = await response.arrayBuffer();
  const decoded = dnsPacket.decode(Buffer.from(responseArrayBuffer));

  // Check response code (RCODE)
  const rcode = (decoded.flags ?? 0) & 0x0f;
  if (rcode !== 0) {
    const statusMessages: Record<number, string> = {
      1: "Format error",
      2: "Server failure",
      3: "Non-existent domain",
      4: "Not implemented",
      5: "Query refused",
    };
    throw new Error(statusMessages[rcode] || `DNS error: ${rcode}`);
  }

  // Check AD (Authenticated Data) flag for DNSSEC
  const adFlag = ((decoded.flags ?? 0) & dnsPacket.AUTHENTIC_DATA) !== 0;
  const dnssec: DnssecInfo | null = dnssecValidate
    ? { validated: adFlag, enabled: true }
    : null;

  if (!decoded.answers || decoded.answers.length === 0) {
    return { records: [], dnssec };
  }

  // Filter answers to only include the requested type
  const answers = decoded.answers.filter((a) => a.type === type);

  // Parse the data based on record type
  const records = answers.map((answer) => {
    // deno-lint-ignore no-explicit-any
    const data = (answer as any).data;
    switch (type) {
      case "MX": {
        const mx = data as { preference: number; exchange: string };
        return {
          preference: mx.preference,
          exchange: mx.exchange.replace(/\.$/, ""),
        };
      }
      case "SOA": {
        const soa = data as {
          mname: string;
          rname: string;
          serial: number;
          refresh: number;
          retry: number;
          expire: number;
          minimum: number;
        };
        return {
          mname: soa.mname.replace(/\.$/, ""),
          rname: soa.rname.replace(/\.$/, ""),
          serial: soa.serial,
          refresh: soa.refresh,
          retry: soa.retry,
          expire: soa.expire,
          minimum: soa.minimum,
        };
      }
      case "TXT": {
        // TXT records come as Uint8Array arrays, convert to strings
        const txtData = data as Uint8Array[];
        return txtData.map((buf) => new TextDecoder().decode(buf));
      }
      case "CNAME":
      case "NS":
      case "PTR":
        // Remove trailing dot from domain names
        return (data as string).replace(/\.$/, "");
      default:
        return data;
    }
  });

  return { records, dnssec };
}

async function resolveWithQuad9DoH(
  domain: string,
  type: RecordType,
  dnssecValidate: boolean = false
): Promise<DoHResult> {
  // Quad9 DoH using RFC 8484 binary wire format
  return resolveWithBinaryDoH(
    domain,
    type,
    "https://dns.quad9.net/dns-query",
    "Quad9",
    dnssecValidate
  );
}

export const handler = define.handlers({
  async GET(ctx) {
    const url = new URL(ctx.req.url);
    const domain = url.searchParams.get("domain");
    const type = url.searchParams.get("type") as RecordType | null;
    const resolver = url.searchParams.get("resolver") || "system";
    const dnssec = url.searchParams.get("dnssec") === "true";

    if (!domain) {
      return Response.json(
        { success: false, error: "Domain is required" },
        { status: 400 }
      );
    }

    if (!type) {
      return Response.json(
        { success: false, error: "Record type is required" },
        { status: 400 }
      );
    }

    const validTypes: RecordType[] = [
      "A",
      "AAAA",
      "CNAME",
      "MX",
      "NS",
      "TXT",
      "SOA",
      "PTR",
    ];
    if (!validTypes.includes(type)) {
      return Response.json(
        { success: false, error: `Invalid record type: ${type}` },
        { status: 400 }
      );
    }

    try {
      const startTime = performance.now();

      const resolvers: Record<string, (domain: string, type: RecordType, dnssec: boolean) => Promise<DoHResult>> = {
        google: resolveWithGoogleDoH,
        cloudflare: resolveWithCloudflareDoH,
        "cloudflare-security": resolveWithCloudflareSecurityDoH,
        "cloudflare-family": resolveWithCloudflareFamilyDoH,
        quad9: resolveWithQuad9DoH,
      };

      const resolveFn = resolvers[resolver] ?? resolvers.google;
      const { records, dnssec: dnssecInfo } = await resolveFn(domain, type, dnssec);

      const endTime = performance.now();
      const queryTime = Math.round(endTime - startTime);

      return Response.json({
        success: true,
        domain,
        recordType: type,
        resolver,
        records,
        queryTime,
        ...(dnssecInfo && { dnssec: dnssecInfo }),
      });
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : "DNS lookup failed";
      return Response.json(
        { success: false, error: errorMessage },
        { status: 500 }
      );
    }
  },
});
