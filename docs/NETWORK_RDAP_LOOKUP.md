# ARIN and RIPE Address-Space Lookup

Network Monitor and Network Intelligence include a reusable RDAP lookup. Select a live connection to prefill its remote IP, or paste an IP from a saved snapshot or prior evidence. Each lookup requires consent because the address is disclosed to the selected registry.

ARIN bootstrap can redirect to the authoritative RIR; redirects are restricted to allowlisted HTTPS ARIN and RIPE RDAP hosts. RIPE performs a direct RIPE RDAP query. Results retain provider, authoritative host, retrieval time, network range, handle, organization fields, status, and source URL. Registration data does not prove who operated a particular connection or whether it was approved, benign, or malicious.

The ARIN endpoint follows [ARIN's official RDAP documentation](https://www.arin.net/resources/registry/whois/rdap/).
