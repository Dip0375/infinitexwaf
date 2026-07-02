/**
 * InfiniteX - Threat Intelligence Service
 * Fetches, parses, and maintains open-source threat intel feeds.
 * Provides fast IP lookup for the WAF engine.
 */

import * as https from 'https';
import * as http from 'http';
import { THREAT_FEEDS, ThreatFeed, ThreatEntry } from './feeds';

export interface ThreatLookupResult {
  found: boolean;
  ip: string;
  feeds: string[];
  categories: string[];
  confidence: number;
  tags: string[];
}

export interface FeedStats {
  feed: ThreatFeed;
  ipCount: number;
  lastUpdated?: Date;
  status: 'ok' | 'error' | 'pending' | 'disabled';
  error?: string;
}

export class ThreatIntelService {
  // Primary lookup set — plain IPs for O(1) lookup
  private ipSet = new Set<string>();

  // CIDR ranges for subnet matching
  private cidrRanges: Array<{ cidr: string; feedId: string; category: string }> = [];

  // Detailed entry map for enrichment
  private entryMap = new Map<string, ThreatEntry[]>();

  // Feed state tracking
  private feedStats = new Map<string, FeedStats>();

  // Update timers
  private updateTimers = new Map<string, NodeJS.Timeout>();

  // Stats
  private totalBlocked = 0;
  private lookupCount = 0;

  constructor() {
    // Initialize feed stats
    for (const feed of THREAT_FEEDS) {
      this.feedStats.set(feed.id, {
        feed: { ...feed },
        ipCount: 0,
        status: feed.enabled ? 'pending' : 'disabled',
      });
    }
  }

  /**
   * Start all enabled feeds
   */
  public async start(): Promise<void> {
    const enabledFeeds = THREAT_FEEDS.filter((f) => f.enabled);
    console.log(`[ThreatIntel] Starting ${enabledFeeds.length} threat intel feeds...`);

    // Load all feeds in parallel (with error isolation)
    await Promise.allSettled(enabledFeeds.map((feed) => this.loadFeed(feed)));

    // Schedule periodic updates
    for (const feed of enabledFeeds) {
      const intervalMs = feed.updateIntervalHours * 60 * 60 * 1000;
      const timer = setInterval(() => this.loadFeed(feed), intervalMs);
      this.updateTimers.set(feed.id, timer);
    }

    console.log(`[ThreatIntel] Loaded ${this.ipSet.size} IPs + ${this.cidrRanges.length} CIDR ranges`);
  }

  /**
   * Stop all update timers
   */
  public stop(): void {
    for (const timer of this.updateTimers.values()) {
      clearInterval(timer);
    }
    this.updateTimers.clear();
  }

  /**
   * Check if an IP is in any threat feed
   */
  public lookup(ip: string): ThreatLookupResult {
    this.lookupCount++;

    // Fast path: direct IP set lookup
    if (this.ipSet.has(ip)) {
      const entries = this.entryMap.get(ip) || [];
      const feeds = [...new Set(entries.map((e) => e.feedName))];
      const categories = [...new Set(entries.map((e) => e.category))];
      const tags = [...new Set(entries.flatMap((e) => e.tags))];
      const confidence = entries.length > 0
        ? Math.min(100, entries.reduce((a, e) => a + e.confidence, 0) / entries.length + (entries.length - 1) * 10)
        : 80;

      this.totalBlocked++;
      return { found: true, ip, feeds, categories, confidence, tags };
    }

    // CIDR range check
    for (const range of this.cidrRanges) {
      if (this.ipInCidr(ip, range.cidr)) {
        const stat = this.feedStats.get(range.feedId);
        this.totalBlocked++;
        return {
          found: true,
          ip,
          feeds: [stat?.feed.name || range.feedId],
          categories: [range.category],
          confidence: 75,
          tags: ['cidr-match'],
        };
      }
    }

    return { found: false, ip, feeds: [], categories: [], confidence: 0, tags: [] };
  }

  /**
   * Get all feed stats
   */
  public getFeedStats(): FeedStats[] {
    return Array.from(this.feedStats.values());
  }

  /**
   * Get summary stats
   */
  public getSummary() {
    const stats = this.getFeedStats();
    return {
      totalIPs: this.ipSet.size,
      totalCIDRs: this.cidrRanges.length,
      totalFeeds: THREAT_FEEDS.length,
      activeFeeds: stats.filter((s) => s.status === 'ok').length,
      errorFeeds: stats.filter((s) => s.status === 'error').length,
      totalBlocked: this.totalBlocked,
      lookupCount: this.lookupCount,
      lastUpdated: new Date().toISOString(),
      feedBreakdown: stats.map((s) => ({
        id: s.feed.id,
        name: s.feed.name,
        category: s.feed.category,
        ipCount: s.ipCount,
        status: s.status,
        lastUpdated: s.lastUpdated?.toISOString(),
        error: s.error,
        enabled: s.feed.enabled,
        updateIntervalHours: s.feed.updateIntervalHours,
        description: s.feed.description,
      })),
    };
  }

  /**
   * Enable or disable a feed
   */
  public async setFeedEnabled(feedId: string, enabled: boolean): Promise<void> {
    const stat = this.feedStats.get(feedId);
    if (!stat) throw new Error(`Feed ${feedId} not found`);

    stat.feed.enabled = enabled;

    if (enabled) {
      stat.status = 'pending';
      await this.loadFeed(stat.feed);
      const intervalMs = stat.feed.updateIntervalHours * 60 * 60 * 1000;
      const timer = setInterval(() => this.loadFeed(stat.feed), intervalMs);
      this.updateTimers.set(feedId, timer);
    } else {
      stat.status = 'disabled';
      const timer = this.updateTimers.get(feedId);
      if (timer) {
        clearInterval(timer);
        this.updateTimers.delete(feedId);
      }
      // Remove IPs from this feed
      this.removeEntriesForFeed(feedId);
    }
  }

  /**
   * Force refresh a specific feed
   */
  public async refreshFeed(feedId: string): Promise<void> {
    const stat = this.feedStats.get(feedId);
    if (!stat) throw new Error(`Feed ${feedId} not found`);
    await this.loadFeed(stat.feed);
  }

  /**
   * Force refresh all feeds
   */
  public async refreshAll(): Promise<void> {
    const enabled = THREAT_FEEDS.filter((f) => {
      const stat = this.feedStats.get(f.id);
      return stat?.feed.enabled;
    });
    await Promise.allSettled(enabled.map((f) => this.loadFeed(f)));
  }

  // ─── Private ────────────────────────────────────────────────────────────────

  private async loadFeed(feed: ThreatFeed): Promise<void> {
    const stat = this.feedStats.get(feed.id)!;
    stat.status = 'pending';

    try {
      const raw = await this.fetchUrl(feed.url);
      const ips = this.parseFeed(raw, feed);

      // Remove old entries for this feed
      this.removeEntriesForFeed(feed.id);

      // Add new entries
      let count = 0;
      for (const ip of ips) {
        if (feed.format === 'cidr' && ip.includes('/')) {
          this.cidrRanges.push({ cidr: ip, feedId: feed.id, category: feed.category });
          count++;
        } else if (this.isValidIp(ip)) {
          this.ipSet.add(ip);
          const entry: ThreatEntry = {
            ip,
            feedId: feed.id,
            feedName: feed.name,
            category: feed.category,
            addedAt: new Date(),
            confidence: this.getConfidenceForFeed(feed.id),
            tags: [feed.category, feed.id],
          };
          const existing = this.entryMap.get(ip) || [];
          existing.push(entry);
          this.entryMap.set(ip, existing);
          count++;
        }
      }

      stat.ipCount = count;
      stat.lastUpdated = new Date();
      stat.status = 'ok';
      stat.error = undefined;

      console.log(`[ThreatIntel] ${feed.name}: loaded ${count} entries`);
    } catch (err: any) {
      stat.status = 'error';
      stat.error = err.message || String(err);
      console.error(`[ThreatIntel] Failed to load ${feed.name}: ${stat.error}`);
    }
  }

  private parseFeed(raw: string, feed: ThreatFeed): string[] {
    const lines = raw.split('\n');
    const results: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();

      // Skip comments and empty lines
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;

      if (feed.format === 'csv') {
        // Take first column
        const parts = trimmed.split(',');
        if (parts[0]) results.push(parts[0].trim());
      } else if (feed.format === 'cidr') {
        // Accept both plain IPs and CIDR notation
        const ip = trimmed.split(';')[0].split(' ')[0].trim();
        if (ip) results.push(ip);
      } else {
        // Plain IP list — take first token
        const ip = trimmed.split(/\s+/)[0];
        if (ip) results.push(ip);
      }
    }

    return results;
  }

  private removeEntriesForFeed(feedId: string): void {
    // Remove CIDR ranges for this feed
    this.cidrRanges = this.cidrRanges.filter((r) => r.feedId !== feedId);

    // Remove IP entries for this feed
    for (const [ip, entries] of this.entryMap.entries()) {
      const remaining = entries.filter((e) => e.feedId !== feedId);
      if (remaining.length === 0) {
        this.entryMap.delete(ip);
        this.ipSet.delete(ip);
      } else {
        this.entryMap.set(ip, remaining);
      }
    }
  }

  private fetchUrl(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const client = url.startsWith('https') ? https : http;
      const req = client.get(url, { timeout: 15000 }, (res) => {
        if (res.statusCode && res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
        res.on('error', reject);
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    });
  }

  private isValidIp(ip: string): boolean {
    // IPv4
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4.test(ip)) {
      return ip.split('.').every((octet) => parseInt(octet) <= 255);
    }
    // IPv6 (basic check)
    return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':');
  }

  private ipInCidr(ip: string, cidr: string): boolean {
    try {
      const [range, bits] = cidr.split('/');
      if (!bits) return ip === range;
      const mask = parseInt(bits, 10);
      if (isNaN(mask)) return false;

      const ipParts = ip.split('.').map(Number);
      const rangeParts = range.split('.').map(Number);
      if (ipParts.length !== 4 || rangeParts.length !== 4) return false;

      const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
      const rangeNum = (rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3];
      const maskNum = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;

      return (ipNum >>> 0 & maskNum) === (rangeNum >>> 0 & maskNum);
    } catch {
      return false;
    }
  }

  private getConfidenceForFeed(feedId: string): number {
    const confidenceMap: Record<string, number> = {
      'tor-exit-nodes': 99,
      'firehol-level1': 95,
      'firehol-level2': 80,
      'emerging-threats-compromised': 85,
      'spamhaus-drop': 95,
      'ipsum': 75,
      'blocklist-de-all': 70,
      'cinsscore': 80,
      'feodo-botnet': 95,
      'sslbl-botnet': 95,
    };
    return confidenceMap[feedId] ?? 75;
  }
}

// Singleton
export const threatIntelService = new ThreatIntelService();
