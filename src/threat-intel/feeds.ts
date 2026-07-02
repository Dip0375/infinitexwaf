/**
 * InfiniteX - Open Source Threat Intelligence Feeds
 * Integrates: Tor exit nodes, Firehol, Emerging Threats, Spamhaus DROP,
 *             AbuseIPDB (free tier), ipsum, and blocklist.de
 */

import * as https from 'https';
import * as http from 'http';

export interface ThreatFeed {
  id: string;
  name: string;
  url: string;
  description: string;
  category: 'tor' | 'proxy' | 'vpn' | 'botnet' | 'scanner' | 'spam' | 'malware' | 'mixed';
  format: 'plain' | 'cidr' | 'csv';
  enabled: boolean;
  updateIntervalHours: number;
  lastUpdated?: Date;
  ipCount?: number;
  error?: string;
}

export interface ThreatEntry {
  ip: string;
  feedId: string;
  feedName: string;
  category: ThreatFeed['category'];
  addedAt: Date;
  confidence: number; // 0-100
  tags: string[];
}

// Public open-source threat intel feeds (no API key required)
export const THREAT_FEEDS: ThreatFeed[] = [
  {
    id: 'tor-exit-nodes',
    name: 'Tor Exit Nodes (Official)',
    url: 'https://check.torproject.org/torbulkexitlist',
    description: 'Official Tor Project bulk exit node list',
    category: 'tor',
    format: 'plain',
    enabled: true,
    updateIntervalHours: 1,
  },
  {
    id: 'firehol-level1',
    name: 'Firehol Level 1',
    url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    description: 'Firehol Level 1 - Absolutely certain blocklist (CIDRs)',
    category: 'mixed',
    format: 'cidr',
    enabled: true,
    updateIntervalHours: 24,
  },
  {
    id: 'firehol-level2',
    name: 'Firehol Level 2',
    url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset',
    description: 'Firehol Level 2 - Blocklist for average security',
    category: 'mixed',
    format: 'cidr',
    enabled: false,
    updateIntervalHours: 24,
  },
  {
    id: 'emerging-threats-compromised',
    name: 'Emerging Threats - Compromised IPs',
    url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    description: 'Emerging Threats known compromised/infected hosts',
    category: 'botnet',
    format: 'plain',
    enabled: true,
    updateIntervalHours: 12,
  },
  {
    id: 'spamhaus-drop',
    name: 'Spamhaus DROP',
    url: 'https://www.spamhaus.org/drop/drop.txt',
    description: 'Spamhaus Do Not Route Or Peer list - hijacked netblocks',
    category: 'spam',
    format: 'cidr',
    enabled: true,
    updateIntervalHours: 24,
  },
  {
    id: 'ipsum',
    name: 'IPsum (Level 3)',
    url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
    description: 'IPsum threat intelligence feed - IPs seen in 3+ blacklists',
    category: 'mixed',
    format: 'plain',
    enabled: true,
    updateIntervalHours: 24,
  },
  {
    id: 'blocklist-de-all',
    name: 'Blocklist.de - All Attacks',
    url: 'https://lists.blocklist.de/lists/all.txt',
    description: 'IPs that have been reported for attacks (SSH, FTP, web, etc.)',
    category: 'scanner',
    format: 'plain',
    enabled: false,
    updateIntervalHours: 6,
  },
  {
    id: 'cinsscore',
    name: 'CINS Army List',
    url: 'https://cinsscore.com/list/ci-badguys.txt',
    description: 'CINS Score bad guys list - active threat actors',
    category: 'mixed',
    format: 'plain',
    enabled: true,
    updateIntervalHours: 12,
  },
  {
    id: 'feodo-botnet',
    name: 'Feodo Tracker - Botnet C2',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    description: 'Abuse.ch Feodo Tracker - botnet C2 server IPs',
    category: 'botnet',
    format: 'plain',
    enabled: true,
    updateIntervalHours: 6,
  },
  {
    id: 'sslbl-botnet',
    name: 'SSLBL - SSL Botnet C2',
    url: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
    description: 'Abuse.ch SSL Blacklist - botnet C2 IPs using SSL',
    category: 'botnet',
    format: 'plain',
    enabled: true,
    updateIntervalHours: 6,
  },
];
