"""Deduplication helpers for vulnerabilities and indicators."""
def deduplicate_vulnerabilities(vuln_list):
    """Remove duplicate vulnerabilities based on CVE ID"""
    seen_cves = {}
    deduplicated = []

    for vuln in vuln_list:
        cve_id = vuln.get('cve_id', '').upper()
        if cve_id and cve_id != 'N/A':
            if cve_id in seen_cves:
                # Update existing entry with higher confidence source
                existing = seen_cves[cve_id]
                if vuln.get('confidence_score', 0) > existing.get('confidence_score', 0):
                    seen_cves[cve_id] = vuln
                    # Replace in deduplicated list
                    for i, item in enumerate(deduplicated):
                        if item.get('cve_id') == cve_id:
                            deduplicated[i] = vuln
                            break
            else:
                seen_cves[cve_id] = vuln
                deduplicated.append(vuln)
        else:
            # No CVE ID, add as-is
            deduplicated.append(vuln)

    return deduplicated

def deduplicate_indicators(ioc_list):
    """Remove duplicate IOCs based on indicator value"""
    seen_indicators = {}
    deduplicated = []

    for ioc in ioc_list:
        indicator = ioc.get('indicator', '').lower().strip()
        if indicator:
            if indicator in seen_indicators:
                # Keep the one with higher confidence
                existing = seen_indicators[indicator]
                if ioc.get('confidence_score', 0) > existing.get('confidence_score', 0):
                    seen_indicators[indicator] = ioc
                    # Replace in deduplicated list
                    for i, item in enumerate(deduplicated):
                        if item.get('indicator', '').lower().strip() == indicator:
                            deduplicated[i] = ioc
                            break
            else:
                seen_indicators[indicator] = ioc
                deduplicated.append(ioc)
        else:
            deduplicated.append(ioc)

    return deduplicated
