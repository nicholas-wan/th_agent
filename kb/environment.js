// ════════════════════════════════════════════════════════════════════════════
// ENVIRONMENT CONTEXT  —  kb/environment.js
// ════════════════════════════════════════════════════════════════════════════
// Empty shell — data is loaded at runtime from kb/environment.md.
// Edit kb/environment.md to update the environment context.
//
// On first Knowledge Base tab open, initKbTab() fetches environment.md,
// parses it, and populates these globals in-place.
// ════════════════════════════════════════════════════════════════════════════

const envData = {
  domain: {
    name: 'CORP.LOCAL', netbios: 'CORP', forest: 'CORP.LOCAL',
    functionalLevel: '', adfsUrl: '', adSync: '',
    dcs: [], sites: [], trusts: [],
  },
  stats:          [],
  anomalies:      [],
  segments:       [],
  assets:         [],
  accounts:       [],
  topology:       '',
  infrastructure: [],
};

const crownJewels = {
  assets:   [],
  accounts: [],
};
