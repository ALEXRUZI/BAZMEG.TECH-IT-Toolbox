// Evidence uses response-local JSON pointers or 1-based WHOIS lines. The lookup
// layer adds the actual final service; no parser initiates additional requests.
export const OVERVIEW_FIELDS = ["Domain", "Created", "Updated", "Expires", "Nameservers", "Published DNSSEC",
  "Registrant name", "Registrant organization", "Registrant organization ID", "Registrant phone", "Registrant email",
  "Registrar", "Registrar organization", "Registrar code", "Registrar phone", "Registrar email"];
export function registrationDate(value) {
  const m = value.match(/^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2})))?$/);
  if (!m) return false;
  const y = Number(m[1]), month = Number(m[2]), day = Number(m[3]);
  const days = [31, y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1] && (!m[4] || Number(m[4]) <= 23 && Number(m[5]) <= 59 && Number(m[6]) <= 59 && Number(m[7] ?? 0) <= 23 && Number(m[8] ?? 0) <= 59);
}
export function evidenceCollector(protocol, source = null) {
  const evidence = Object.create(null), unsupported = new Set(), ambiguous = new Set();
  return {
    evidence, unsupported, ambiguous,
    add(label, value, record, role, location, state = "available") {
      if (typeof value !== "string" || !value.trim()) return;
      (evidence[label] ??= []).push({ value: value.trim(), record, role, location, state });
    },
    finish(fields, extraConflicts = []) {
      const conflicts = new Set(extraConflicts), attribution = Object.create(null);
      // Conflicting identity properties cannot lend their remaining contact
      // details to a synthetic single person/company in the primary card.
      for (const role of ["registrant", "registrar"]) {
        const identity = role === "registrant" ? ["Registrant name", "Registrant organization", "Registrant organization ID"] : ["Registrar", "Registrar organization"];
        if (identity.some((label) => new Set((evidence[label] ?? []).map((e) => e.value)).size > 1)) {
          for (const label of Object.keys(evidence)) if (role === "registrar" ? /^Registrar(?: |$)/.test(label) : label.startsWith("Registrant ")) ambiguous.add(label);
        }
      }
      for (const label of new Set([...OVERVIEW_FIELDS, ...Object.keys(evidence)])) {
        const entries = evidence[label] ?? [], values = [...new Set(entries.map((e) => e.value))];
        const records = new Set(entries.map((e) => e.record));
        const list = ["Nameservers", "Status", "DS", "DNSKEY evidence", "Registrant phone", "Registrant email", "Registrar phone", "Registrar email"].includes(label);
        const conflict = ambiguous.has(label) || (!list && values.length > 1) || (/^(?:Registrant |Registrar(?: |$))/.test(label) && records.size > 1 && values.length > 1);
        const invalidDate = ["Created", "Updated", "Expires"].includes(label) && values.some((value) => !registrationDate(value));
        const state = conflict ? "ambiguous" : invalidDate ? "unsupported" : entries.some((e) => e.state === "redacted") ? "redacted" : values.length ? "available" : unsupported.has(label) ? "unsupported" : "missing";
        attribution[label] = { state, protocol, source, evidence: entries };
        if (conflict) { conflicts.add(label); delete fields[label]; }
        else if (invalidDate) delete fields[label];
        else if (values.length) fields[label] = values;
      }
      return { attribution, conflicts: [...conflicts] };
    },
  };
}
