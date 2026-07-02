/**
 * InfiniteX - Threat Intelligence API Routes
 */

import express from 'express';
import { threatIntelService } from './service';

const router = express.Router();

/**
 * GET /api/threat-intel/summary
 * Overall stats: total IPs, active feeds, blocked count
 */
router.get('/summary', (_req, res) => {
  res.json(threatIntelService.getSummary());
});

/**
 * GET /api/threat-intel/feeds
 * List all feeds with status
 */
router.get('/feeds', (_req, res) => {
  const summary = threatIntelService.getSummary();
  res.json({ feeds: summary.feedBreakdown });
});

/**
 * POST /api/threat-intel/feeds/:id/enable
 * Enable a feed
 */
router.post('/feeds/:id/enable', async (req, res) => {
  try {
    await threatIntelService.setFeedEnabled(req.params.id, true);
    res.json({ success: true });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/threat-intel/feeds/:id/disable
 * Disable a feed
 */
router.post('/feeds/:id/disable', async (req, res) => {
  try {
    await threatIntelService.setFeedEnabled(req.params.id, false);
    res.json({ success: true });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/threat-intel/feeds/:id/refresh
 * Force refresh a specific feed
 */
router.post('/feeds/:id/refresh', async (req, res) => {
  try {
    await threatIntelService.refreshFeed(req.params.id);
    res.json({ success: true });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/threat-intel/refresh-all
 * Force refresh all enabled feeds
 */
router.post('/refresh-all', async (_req, res) => {
  try {
    await threatIntelService.refreshAll();
    res.json({ success: true, summary: threatIntelService.getSummary() });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/threat-intel/lookup?ip=1.2.3.4
 * Check if an IP is in any threat feed
 */
router.get('/lookup', (req, res) => {
  const ip = req.query.ip as string;
  if (!ip) {
    return res.status(400).json({ error: 'ip query parameter required' });
  }
  const result = threatIntelService.lookup(ip);
  res.json(result);
});

export default router;
