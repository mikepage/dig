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

export const handler = define.handlers({
  async GET(ctx) {
    const url = new URL(ctx.req.url);
    const domain = url.searchParams.get("domain");
    const type = url.searchParams.get("type") as RecordType | null;
    const nameServer = url.searchParams.get("nameServer");

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

      const options: Deno.ResolveDnsOptions = {};
      if (nameServer) {
        options.nameServer = {
          ipAddr: nameServer,
          port: 53,
        };
      }

      const records = await Deno.resolveDns(domain, type, options);

      const endTime = performance.now();
      const queryTime = Math.round(endTime - startTime);

      return Response.json({
        success: true,
        domain,
        recordType: type,
        nameServer: nameServer || null,
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
