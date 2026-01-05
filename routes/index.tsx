import { Head } from "fresh/runtime";
import { define } from "../utils.ts";
import DnsLookup from "../islands/DnsLookup.tsx";

export default define.page(function Home() {
  return (
    <div class="min-h-screen bg-[#fafafa]">
      <Head>
        <title>DNS Lookup</title>
      </Head>
      <div class="px-6 md:px-12 py-8">
        <div class="max-w-4xl mx-auto">
          <h1 class="text-2xl font-normal text-[#111] tracking-tight mb-2">
            DNS Lookup
          </h1>
          <p class="text-[#666] text-sm mb-8">
            Query DNS records for any domain. Supports A, AAAA, CNAME, MX, NS,
            TXT, SOA, and PTR record types.
          </p>
          <DnsLookup />
        </div>
      </div>
    </div>
  );
});
