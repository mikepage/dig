import { define } from "../../utils.ts";

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

async function resolveWithGoogleDoH(
  domain: string,
  type: RecordType
): Promise<unknown[]> {
  const typeNum = DNS_TYPE_MAP[type];
  const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${typeNum}`;

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

  if (!data.Answer) {
    return [];
  }

  // Filter answers to only include the requested type
  const answers = data.Answer.filter((a) => a.type === typeNum);

  // Parse the data based on record type
  return answers.map((answer) => {
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
}

export const handler = define.handlers({
  async GET(ctx) {
    const url = new URL(ctx.req.url);
    const domain = url.searchParams.get("domain");
    const type = url.searchParams.get("type") as RecordType | null;
    const resolver = url.searchParams.get("resolver") || "system";

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

      let records: unknown[];
      if (resolver === "google") {
        records = await resolveWithGoogleDoH(domain, type);
      } else {
        records = await Deno.resolveDns(domain, type);
      }

      const endTime = performance.now();
      const queryTime = Math.round(endTime - startTime);

      return Response.json({
        success: true,
        domain,
        recordType: type,
        resolver,
        records,
        queryTime,
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
