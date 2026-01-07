import { useSignal } from "@preact/signals";
import { useEffect } from "preact/hooks";

const RecordTypes = [
  { value: "A", label: "A - IPv4 Address" },
  { value: "AAAA", label: "AAAA - IPv6 Address" },
  { value: "CNAME", label: "CNAME - Canonical Name" },
  { value: "MX", label: "MX - Mail Exchange" },
  { value: "NS", label: "NS - Name Server" },
  { value: "TXT", label: "TXT - Text Record" },
  { value: "SOA", label: "SOA - Start of Authority" },
  { value: "PTR", label: "PTR - Pointer Record" },
];

const Resolvers = [
  { value: "google", label: "Google (8.8.8.8)" },
  { value: "cloudflare", label: "Cloudflare (1.1.1.1)" },
  { value: "cloudflare-security", label: "Cloudflare Security (1.1.1.2)" },
  { value: "cloudflare-family", label: "Cloudflare Family (1.1.1.3)" },
];


interface DnssecInfo {
  validated: boolean;
  enabled: boolean;
}

interface DnsResult {
  recordType: string;
  domain: string;
  records: unknown[];
  queryTime: number;
  dnssec?: DnssecInfo;
}

const ValidRecordTypes = RecordTypes.map((r) => r.value);

function parseHash(hash: string): { type: string; domain: string } | null {
  // Format: #TYPE/domain or #TYPE/domain/
  const match = hash.match(/^#([A-Z]+)\/(.+?)\/?\s*$/i);
  if (!match) return null;

  const type = match[1].toUpperCase();
  const domain = match[2];

  if (!ValidRecordTypes.includes(type)) return null;
  if (!domain) return null;

  return { type, domain };
}

function updateHash(type: string, domain: string) {
  if (domain) {
    window.history.replaceState(null, "", `#${type}/${domain}`);
  } else {
    window.history.replaceState(null, "", window.location.pathname);
  }
}

export default function DnsLookup() {
  const domain = useSignal("");
  const recordType = useSignal("A");
  const resolver = useSignal("google");
  const dnssecValidate = useSignal(true); // Enabled by default for DoH resolvers
  const isLoading = useSignal(false);
  const result = useSignal<DnsResult | null>(null);
  const error = useSignal<string | null>(null);
  const initialLoadDone = useSignal(false);

  const handleLookup = async () => {
    error.value = null;
    result.value = null;

    const domainValue = domain.value.trim();
    if (!domainValue) {
      error.value = "Please enter a domain name";
      return;
    }

    isLoading.value = true;

    try {
      const params = new URLSearchParams({
        domain: domainValue,
        type: recordType.value,
        resolver: resolver.value,
      });

      // Include dnssec param for DoH resolvers
      if (resolver.value === "google" || resolver.value === "cloudflare" || resolver.value === "cloudflare-security" || resolver.value === "cloudflare-family") {
        params.set("dnssec", dnssecValidate.value ? "true" : "false");
      }

      const response = await fetch(`/api/dns?${params}`);
      const data = await response.json();

      if (!data.success) {
        error.value = data.error || "DNS lookup failed";
        return;
      }

      result.value = data;
    } catch {
      error.value = "Failed to perform DNS lookup";
    } finally {
      isLoading.value = false;
    }
  };

  const handleClear = () => {
    domain.value = "";
    recordType.value = "A";
    resolver.value = "google";
    dnssecValidate.value = true;
    result.value = null;
    error.value = null;
    updateHash("A", "");
  };

  // Parse URL hash on mount and handle hash changes
  useEffect(() => {
    const handleHashChange = () => {
      const parsed = parseHash(window.location.hash);
      if (parsed) {
        domain.value = parsed.domain;
        recordType.value = parsed.type;
        // Auto-lookup if this is initial load with hash
        if (!initialLoadDone.value) {
          initialLoadDone.value = true;
          handleLookup();
        }
      } else {
        initialLoadDone.value = true;
      }
    };

    // Initial parse
    handleHashChange();

    // Listen for hash changes
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  // Update URL hash when domain or record type changes
  useEffect(() => {
    if (initialLoadDone.value) {
      updateHash(recordType.value, domain.value.trim());
    }
  }, [domain.value, recordType.value]);

  const formatRecord = (record: unknown, type: string): string => {
    if (typeof record === "string") {
      return record;
    }
    if (type === "TXT" && Array.isArray(record)) {
      return record.join("");
    }
    if (type === "MX" && typeof record === "object" && record !== null) {
      const mx = record as { preference: number; exchange: string };
      return `${mx.preference} ${mx.exchange}`;
    }
    if (type === "SOA" && typeof record === "object" && record !== null) {
      const soa = record as {
        mname: string;
        rname: string;
        serial: number;
        refresh: number;
        retry: number;
        expire: number;
        minimum: number;
      };
      return `Primary NS: ${soa.mname}\nAdmin: ${soa.rname}\nSerial: ${soa.serial}\nRefresh: ${soa.refresh}s\nRetry: ${soa.retry}s\nExpire: ${soa.expire}s\nMinimum TTL: ${soa.minimum}s`;
    }
    return JSON.stringify(record, null, 2);
  };

  return (
    <div class="w-full">
      {/* Input Section */}
      <div class="bg-white rounded-lg shadow p-6 mb-6">
        <h2 class="text-lg font-semibold text-gray-800 mb-4">DNS Query</h2>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          <div class="md:col-span-2">
            <label class="block text-sm font-medium text-gray-700 mb-1">
              Domain Name
            </label>
            <input
              type="text"
              value={domain.value}
              onInput={(e) =>
                (domain.value = (e.target as HTMLInputElement).value)
              }
              onKeyDown={(e) => {
                if (e.key === "Enter") handleLookup();
              }}
              placeholder="example.com"
              class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500 font-mono text-sm"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">
              Record Type
            </label>
            <select
              value={recordType.value}
              onChange={(e) =>
                (recordType.value = (e.target as HTMLSelectElement).value)
              }
              class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              {RecordTypes.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">
              DNS Resolver
            </label>
            <select
              value={resolver.value}
              onChange={(e) => {
                resolver.value = (e.target as HTMLSelectElement).value;
                // Reset DNSSEC to enabled when switching resolvers
                dnssecValidate.value = true;
              }}
              class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              {Resolvers.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* DNSSEC Validation Option - visible for DoH resolvers */}
        {(resolver.value === "google" || resolver.value === "cloudflare" || resolver.value === "cloudflare-security" || resolver.value === "cloudflare-family") && (
          <div class="mb-4">
            <span class="block text-sm font-medium text-gray-700 mb-2">
              DNSSEC Validation
            </span>
            <div class="flex gap-6">
              <label class="inline-flex items-center cursor-pointer">
                <input
                  type="radio"
                  name="dnssec"
                  checked={dnssecValidate.value}
                  onChange={() => (dnssecValidate.value = true)}
                  class="w-4 h-4 text-blue-600 border-gray-300 focus:ring-blue-500"
                />
                <span class="ml-2 text-sm text-gray-700">Enabled</span>
              </label>
              <label class="inline-flex items-center cursor-pointer">
                <input
                  type="radio"
                  name="dnssec"
                  checked={!dnssecValidate.value}
                  onChange={() => (dnssecValidate.value = false)}
                  class="w-4 h-4 text-blue-600 border-gray-300 focus:ring-blue-500"
                />
                <span class="ml-2 text-sm text-gray-700">Disabled</span>
                <span class="ml-1 text-xs text-gray-500">(cd flag)</span>
              </label>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div class="flex flex-wrap gap-3">
          <button
            onClick={handleLookup}
            disabled={!domain.value.trim() || isLoading.value}
            class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
          >
            {isLoading.value ? "Looking up..." : "Lookup"}
          </button>
          <button
            onClick={handleClear}
            class="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Error */}
      {error.value && (
        <div class="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <p class="text-red-600">{error.value}</p>
        </div>
      )}

      {/* Results */}
      {result.value && (
        <div class="bg-white rounded-lg shadow p-6 mb-6">
          <h3 class="text-lg font-semibold text-gray-800 mb-4">
            DNS Records for {result.value.domain}
          </h3>

          <div class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <span class="text-sm text-gray-500">Record Type</span>
                <p class="font-mono text-sm bg-gray-50 p-2 rounded mt-1">
                  {result.value.recordType}
                </p>
              </div>
              <div>
                <span class="text-sm text-gray-500">Query Time</span>
                <p class="font-mono text-sm bg-gray-50 p-2 rounded mt-1">
                  {result.value.queryTime}ms
                </p>
              </div>
              {result.value.dnssec && (
                <div>
                  <span class="text-sm text-gray-500">DNSSEC Status</span>
                  <p
                    class={`font-mono text-sm p-2 rounded mt-1 ${
                      result.value.dnssec.validated
                        ? "bg-green-50 text-green-700"
                        : "bg-yellow-50 text-yellow-700"
                    }`}
                  >
                    {result.value.dnssec.validated ? "Validated (AD)" : "Not Signed"}
                  </p>
                </div>
              )}
            </div>

            <div>
              <span class="text-sm text-gray-500">
                Records ({result.value.records.length})
              </span>
              <div class="mt-1 space-y-2">
                {result.value.records.length === 0 ? (
                  <p class="font-mono text-sm bg-gray-50 p-2 rounded text-gray-500">
                    No records found
                  </p>
                ) : (
                  result.value.records.map((record, index) => (
                    <pre
                      key={index}
                      class="font-mono text-sm bg-gray-50 p-2 rounded break-all whitespace-pre-wrap"
                    >
                      {formatRecord(record, result.value!.recordType)}
                    </pre>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Reference Section */}
      <details class="bg-white rounded-lg shadow">
        <summary class="p-4 cursor-pointer font-medium text-gray-800 hover:bg-gray-50">
          DNS Record Type Reference
        </summary>
        <div class="p-4 pt-0 border-t">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-gray-500">
                <th class="pb-2">Type</th>
                <th class="pb-2">Description</th>
                <th class="pb-2">Common Use</th>
              </tr>
            </thead>
            <tbody class="text-gray-700">
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">A</td>
                <td class="py-2">IPv4 Address</td>
                <td class="py-2">Maps domain to IPv4</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">AAAA</td>
                <td class="py-2">IPv6 Address</td>
                <td class="py-2">Maps domain to IPv6</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">CNAME</td>
                <td class="py-2">Canonical Name</td>
                <td class="py-2">Domain alias</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">MX</td>
                <td class="py-2">Mail Exchange</td>
                <td class="py-2">Email server routing</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">NS</td>
                <td class="py-2">Name Server</td>
                <td class="py-2">Authoritative DNS servers</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">TXT</td>
                <td class="py-2">Text Record</td>
                <td class="py-2">SPF, DKIM, verification</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">SOA</td>
                <td class="py-2">Start of Authority</td>
                <td class="py-2">Zone configuration</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">PTR</td>
                <td class="py-2">Pointer Record</td>
                <td class="py-2">Reverse DNS lookup</td>
              </tr>
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
