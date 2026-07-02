import { useState } from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import {
  FileBarChart, Download, Shield, Activity, Globe,
  AlertTriangle, Bot, CheckCircle, Clock, Loader2,
  FileText, TrendingUp, BarChart2,
} from 'lucide-react';
import toast from 'react-hot-toast';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

// ── Types ─────────────────────────────────────────────────────────────────────
type ReportType = 'executive' | 'traffic' | 'threats' | 'full';
type ReportFormat = 'pdf';

interface ReportConfig {
  type: ReportType;
  title: string;
  description: string;
  icon: any;
  color: string;
  sections: string[];
}

const REPORT_TYPES: ReportConfig[] = [
  {
    type: 'executive',
    title: 'Executive Summary',
    description: 'High-level security posture overview for management. Includes KPIs, risk score, and key findings.',
    icon: FileText,
    color: 'text-cyan-400',
    sections: ['Security KPIs', 'Risk Assessment', 'Top Threats', 'Recommendations'],
  },
  {
    type: 'traffic',
    title: 'Traffic Analysis Report',
    description: 'Detailed breakdown of all traffic — allowed, blocked, bot, logged — with top IPs, paths, and user agents.',
    icon: Activity,
    color: 'text-green-400',
    sections: ['Traffic Summary', 'Top 10 IPs', 'Top 10 URI Paths', 'Top 10 User Agents', 'Geo Distribution'],
  },
  {
    type: 'threats',
    title: 'Threat Intelligence Report',
    description: 'WAF rule hits, attack categories, severity breakdown, and blocked request details.',
    icon: Shield,
    color: 'text-red-400',
    sections: ['Attack Summary', 'Top 10 WAF Rules', 'Severity Breakdown', 'Attack Categories', 'Top Countries'],
  },
  {
    type: 'full',
    title: 'Full Security Report',
    description: 'Complete report combining all sections — executive summary, traffic, threats, and geo intelligence.',
    icon: BarChart2,
    color: 'text-purple-400',
    sections: ['All sections combined'],
  },
];

// ── PDF Generator ─────────────────────────────────────────────────────────────
function generatePDF(type: ReportType, store: ReturnType<typeof useDashboardStore.getState>) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const { metrics, topIPs, topRules, topPaths, topUserAgents, topCountries, distribution } = store;
  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  const W = 210; // A4 width mm

  // ── Colour palette ──────────────────────────────────────────────────────────
  const C = {
    bg:       [10,  15,  30]  as [number,number,number],
    card:     [17,  24,  39]  as [number,number,number],
    accent:   [6,   182, 212] as [number,number,number],
    red:      [239, 68,  68]  as [number,number,number],
    green:    [16,  185, 129] as [number,number,number],
    purple:   [168, 85,  247] as [number,number,number],
    yellow:   [245, 158, 11]  as [number,number,number],
    white:    [255, 255, 255] as [number,number,number],
    gray:     [107, 114, 128] as [number,number,number],
    lightgray:[55,  65,  81]  as [number,number,number],
  };

  let y = 0;

  // ── Helper: new page with header ────────────────────────────────────────────
  function newPage(title: string) {
    doc.addPage();
    y = 0;
    drawPageHeader(title);
  }

  // ── Cover page ──────────────────────────────────────────────────────────────
  function drawCover() {
    // Dark background
    doc.setFillColor(...C.bg);
    doc.rect(0, 0, W, 297, 'F');

    // Accent bar top
    doc.setFillColor(...C.accent);
    doc.rect(0, 0, W, 3, 'F');

    // Logo area
    doc.setFillColor(...C.card);
    doc.roundedRect(20, 20, 170, 60, 4, 4, 'F');
    doc.setTextColor(...C.accent);
    doc.setFontSize(28);
    doc.setFont('helvetica', 'bold');
    doc.text('InfiniteX WAF', 105, 45, { align: 'center' });
    doc.setFontSize(11);
    doc.setTextColor(...C.gray);
    doc.setFont('helvetica', 'normal');
    doc.text('Advanced Web Application Firewall', 105, 55, { align: 'center' });
    doc.text('Security Intelligence Platform', 105, 62, { align: 'center' });

    // Report title
    const cfg = REPORT_TYPES.find((r) => r.type === type)!;
    doc.setFillColor(...C.accent);
    doc.roundedRect(20, 95, 170, 30, 3, 3, 'F');
    doc.setTextColor(...C.bg);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(cfg.title, 105, 113, { align: 'center' });

    // Meta info
    doc.setFillColor(...C.card);
    doc.roundedRect(20, 140, 170, 50, 3, 3, 'F');
    doc.setTextColor(...C.gray);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    const meta = [
      ['Generated', `${dateStr} at ${timeStr}`],
      ['Report Period', 'Last 24 hours'],
      ['Total Requests', metrics.total.toLocaleString()],
      ['Blocked Requests', metrics.blocked.toLocaleString()],
      ['Threat Level', metrics.blocked / (metrics.total || 1) > 0.2 ? 'HIGH' : metrics.blocked / (metrics.total || 1) > 0.1 ? 'MEDIUM' : 'LOW'],
    ];
    meta.forEach(([k, v], i) => {
      doc.setTextColor(...C.gray);
      doc.text(k, 35, 155 + i * 7);
      doc.setTextColor(...C.white);
      doc.text(String(v), 120, 155 + i * 7);
    });

    // Sections list
    doc.setFillColor(...C.lightgray);
    doc.roundedRect(20, 205, 170, 5, 1, 1, 'F');
    doc.setTextColor(...C.accent);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.text('REPORT CONTENTS', 105, 220, { align: 'center' });
    doc.setTextColor(...C.gray);
    doc.setFont('helvetica', 'normal');
    cfg.sections.forEach((s, i) => {
      doc.text(`• ${s}`, 105, 230 + i * 7, { align: 'center' });
    });

    // Footer
    doc.setFillColor(...C.accent);
    doc.rect(0, 291, W, 6, 'F');
    doc.setTextColor(...C.bg);
    doc.setFontSize(8);
    doc.text('CONFIDENTIAL — InfiniteX WAF Security Report', 105, 295, { align: 'center' });
  }

  // ── Page header ─────────────────────────────────────────────────────────────
  function drawPageHeader(section: string) {
    doc.setFillColor(...C.bg);
    doc.rect(0, 0, W, 297, 'F');
    doc.setFillColor(...C.card);
    doc.rect(0, 0, W, 22, 'F');
    doc.setFillColor(...C.accent);
    doc.rect(0, 0, 3, 22, 'F');
    doc.setTextColor(...C.accent);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text('InfiniteX WAF', 10, 10);
    doc.setTextColor(...C.gray);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.text(section, 10, 17);
    doc.setTextColor(...C.gray);
    doc.text(`${dateStr}  ${timeStr}`, W - 10, 10, { align: 'right' });
    doc.text(`Page ${doc.getNumberOfPages()}`, W - 10, 17, { align: 'right' });
    y = 30;
  }

  // ── Section heading ─────────────────────────────────────────────────────────
  function sectionHeading(title: string, color: [number,number,number] = C.accent) {
    if (y > 260) { newPage(title); return; }
    doc.setFillColor(...color);
    doc.rect(10, y, 4, 8, 'F');
    doc.setTextColor(...color);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text(title, 18, y + 6);
    y += 14;
  }

  // ── KPI cards row ────────────────────────────────────────────────────────────
  function kpiRow(items: { label: string; value: string; color: [number,number,number] }[]) {
    const cardW = (W - 20 - (items.length - 1) * 4) / items.length;
    items.forEach((item, i) => {
      const x = 10 + i * (cardW + 4);
      doc.setFillColor(...C.card);
      doc.roundedRect(x, y, cardW, 22, 2, 2, 'F');
      doc.setFillColor(...item.color);
      doc.rect(x, y, cardW, 2, 'F');
      doc.setTextColor(...item.color);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text(item.value, x + cardW / 2, y + 13, { align: 'center' });
      doc.setTextColor(...C.gray);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'normal');
      doc.text(item.label, x + cardW / 2, y + 19, { align: 'center' });
    });
    y += 28;
  }

  // ── Horizontal bar ───────────────────────────────────────────────────────────
  function hBar(label: string, value: number, max: number, color: [number,number,number], suffix = '') {
    if (y > 270) return;
    doc.setTextColor(...C.gray);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.text(label.slice(0, 38), 12, y + 4);
    doc.setTextColor(...C.white);
    doc.text(`${value.toLocaleString()}${suffix}`, W - 12, y + 4, { align: 'right' });
    doc.setFillColor(...C.lightgray);
    doc.roundedRect(12, y + 6, W - 24, 3, 1, 1, 'F');
    const barW = max > 0 ? ((value / max) * (W - 24)) : 0;
    if (barW > 0) {
      doc.setFillColor(...color);
      doc.roundedRect(12, y + 6, barW, 3, 1, 1, 'F');
    }
    y += 13;
  }

  // ── Severity badge ───────────────────────────────────────────────────────────
  function sevColor(sev: string): [number,number,number] {
    if (sev === 'CRITICAL') return C.red;
    if (sev === 'HIGH')     return [249, 115, 22];
    if (sev === 'MEDIUM')   return C.yellow;
    return C.green;
  }

  // ── Build report ─────────────────────────────────────────────────────────────
  drawCover();

  const blockedPct = metrics.total > 0 ? ((metrics.blocked / metrics.total) * 100).toFixed(1) : '0.0';
  const botPct     = metrics.total > 0 ? ((metrics.bot     / metrics.total) * 100).toFixed(1) : '0.0';
  const allowedPct = metrics.total > 0 ? ((metrics.allowed / metrics.total) * 100).toFixed(1) : '0.0';
  const riskScore  = Math.min(100, Math.round((metrics.blocked / (metrics.total || 1)) * 100 * 3 + (metrics.bot / (metrics.total || 1)) * 100));

  // ── EXECUTIVE SUMMARY ───────────────────────────────────────────────────────
  if (type === 'executive' || type === 'full') {
    newPage('Executive Summary');
    sectionHeading('Security KPIs');
    kpiRow([
      { label: 'Total Requests',   value: metrics.total.toLocaleString(),   color: C.accent  },
      { label: 'Blocked',          value: metrics.blocked.toLocaleString(), color: C.red     },
      { label: 'Allowed',          value: metrics.allowed.toLocaleString(), color: C.green   },
      { label: 'Bot Traffic',      value: metrics.bot.toLocaleString(),     color: C.purple  },
    ]);
    kpiRow([
      { label: 'Block Rate',       value: `${blockedPct}%`,  color: C.red    },
      { label: 'Allow Rate',       value: `${allowedPct}%`,  color: C.green  },
      { label: 'Bot Rate',         value: `${botPct}%`,      color: C.purple },
      { label: 'Risk Score',       value: `${riskScore}/100`,color: riskScore > 60 ? C.red : riskScore > 30 ? C.yellow : C.green },
    ]);

    sectionHeading('Risk Assessment', riskScore > 60 ? C.red : riskScore > 30 ? C.yellow : C.green);
    const riskLevel = riskScore > 60 ? 'HIGH' : riskScore > 30 ? 'MEDIUM' : 'LOW';
    doc.setFillColor(...C.card);
    doc.roundedRect(10, y, W - 20, 28, 3, 3, 'F');
    doc.setFillColor(...(riskScore > 60 ? C.red : riskScore > 30 ? C.yellow : C.green));
    doc.roundedRect(10, y, 3, 28, 1, 1, 'F');
    doc.setTextColor(...(riskScore > 60 ? C.red : riskScore > 30 ? C.yellow : C.green));
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(riskLevel, 20, y + 12);
    doc.setTextColor(...C.gray);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    const riskDesc = riskScore > 60
      ? 'Elevated threat activity detected. Immediate review of blocked requests recommended.'
      : riskScore > 30
      ? 'Moderate threat activity. Monitor blocked requests and review WAF rules.'
      : 'Normal threat levels. WAF is operating within expected parameters.';
    doc.text(riskDesc, 20, y + 20, { maxWidth: W - 35 });
    y += 36;

    sectionHeading('Top Threats Detected');
    const topThreats = topRules.slice(0, 5);
    if (topThreats.length > 0) {
      const maxHits = topThreats[0]?.hits || 1;
      topThreats.forEach((r) => hBar(`${r.name} (${r.ruleId})`, r.hits, maxHits, sevColor(r.severity)));
    } else {
      doc.setTextColor(...C.gray); doc.setFontSize(9);
      doc.text('No threat data available yet.', 12, y); y += 10;
    }

    sectionHeading('Recommendations');
    const recs = [
      riskScore > 60 ? '⚠ Review and tighten WAF rules — block rate is elevated.' : '✓ Block rate is within normal range.',
      parseFloat(botPct) > 10 ? '⚠ High bot traffic detected — consider enabling JS challenge.' : '✓ Bot traffic is within acceptable limits.',
      metrics.logged > 0 ? `ℹ ${metrics.logged.toLocaleString()} requests are in LOG mode — consider switching to BLOCK.` : '✓ No requests in LOG-only mode.',
      '✓ Ensure log export to S3/Azure/GCS is configured for audit trail.',
      '✓ Review Top 10 IPs and consider adding persistent offenders to IP blacklist.',
    ];
    recs.forEach((r) => {
      if (y > 265) return;
      doc.setFillColor(...C.card);
      doc.roundedRect(10, y, W - 20, 10, 2, 2, 'F');
      doc.setTextColor(r.startsWith('⚠') ? C.yellow[0] : r.startsWith('✓') ? C.green[0] : C.accent[0],
                       r.startsWith('⚠') ? C.yellow[1] : r.startsWith('✓') ? C.green[1] : C.accent[1],
                       r.startsWith('⚠') ? C.yellow[2] : r.startsWith('✓') ? C.green[2] : C.accent[2]);
      doc.setFontSize(8);
      doc.text(r, 15, y + 6.5, { maxWidth: W - 30 });
      y += 13;
    });
  }

  // ── TRAFFIC REPORT ──────────────────────────────────────────────────────────
  if (type === 'traffic' || type === 'full') {
    newPage('Traffic Analysis');
    sectionHeading('Traffic Summary', C.green);
    kpiRow([
      { label: 'Total',     value: metrics.total.toLocaleString(),   color: C.accent },
      { label: 'Allowed',   value: metrics.allowed.toLocaleString(), color: C.green  },
      { label: 'Blocked',   value: metrics.blocked.toLocaleString(), color: C.red    },
      { label: 'Logged',    value: metrics.logged.toLocaleString(),  color: C.yellow },
    ]);

    sectionHeading('Traffic Distribution');
    distribution.forEach((d) => {
      const col = d.color.startsWith('#') ? hexToRgb(d.color) : C.accent;
      hBar(d.name, d.value, 100, col, '%');
    });

    sectionHeading('Top 10 IP Addresses', C.accent);
    if (topIPs.length > 0) {
      autoTable(doc, {
        startY: y,
        head: [['#', 'IP Address', 'Requests', 'Share', 'Trend']],
        body: topIPs.slice(0, 10).map((ip, i) => [
          i + 1, ip.name, ip.count.toLocaleString(), `${ip.percentage}%`, ip.trend === 'up' ? '↑' : '↓',
        ]),
        theme: 'plain',
        styles: { fillColor: C.card, textColor: [200, 200, 200], fontSize: 8, cellPadding: 3 },
        headStyles: { fillColor: C.lightgray, textColor: C.accent, fontStyle: 'bold' },
        alternateRowStyles: { fillColor: [20, 28, 45] },
        margin: { left: 10, right: 10 },
      });
      y = (doc as any).lastAutoTable.finalY + 8;
    }

    if (y > 220) newPage('Traffic Analysis — Paths & User Agents');
    sectionHeading('Top 10 URI Paths', C.green);
    if (topPaths.length > 0) {
      autoTable(doc, {
        startY: y,
        head: [['#', 'URI Path', 'Requests', 'Share']],
        body: topPaths.slice(0, 10).map((p, i) => [i + 1, p.name, p.count.toLocaleString(), `${p.percentage}%`]),
        theme: 'plain',
        styles: { fillColor: C.card, textColor: [200, 200, 200], fontSize: 8, cellPadding: 3 },
        headStyles: { fillColor: C.lightgray, textColor: C.green, fontStyle: 'bold' },
        alternateRowStyles: { fillColor: [20, 28, 45] },
        margin: { left: 10, right: 10 },
      });
      y = (doc as any).lastAutoTable.finalY + 8;
    }

    if (y > 200) newPage('Traffic Analysis — User Agents');
    sectionHeading('Top 10 User Agents', C.purple);
    if (topUserAgents.length > 0) {
      autoTable(doc, {
        startY: y,
        head: [['#', 'User Agent', 'Requests', 'Share']],
        body: topUserAgents.slice(0, 10).map((u, i) => [i + 1, u.name.slice(0, 55), u.count.toLocaleString(), `${u.percentage}%`]),
        theme: 'plain',
        styles: { fillColor: C.card, textColor: [200, 200, 200], fontSize: 7, cellPadding: 3 },
        headStyles: { fillColor: C.lightgray, textColor: C.purple, fontStyle: 'bold' },
        alternateRowStyles: { fillColor: [20, 28, 45] },
        margin: { left: 10, right: 10 },
      });
      y = (doc as any).lastAutoTable.finalY + 8;
    }
  }

  // ── THREATS REPORT ──────────────────────────────────────────────────────────
  if (type === 'threats' || type === 'full') {
    newPage('Threat Intelligence');
    sectionHeading('Attack Summary', C.red);
    kpiRow([
      { label: 'Total Blocked',  value: metrics.blocked.toLocaleString(), color: C.red    },
      { label: 'Bot Events',     value: metrics.bot.toLocaleString(),     color: C.purple },
      { label: 'Rules Triggered',value: String(topRules.filter((r) => r.hits > 0).length), color: C.yellow },
      { label: 'Block Rate',     value: `${blockedPct}%`,                 color: C.red    },
    ]);

    sectionHeading('Top 10 WAF Rules Triggered', C.red);
    if (topRules.length > 0) {
      autoTable(doc, {
        startY: y,
        head: [['#', 'Rule ID', 'Rule Name', 'Category', 'Severity', 'Hits']],
        body: topRules.slice(0, 10).map((r, i) => [
          i + 1, r.ruleId, r.name, r.category, r.severity, r.hits.toLocaleString(),
        ]),
        theme: 'plain',
        styles: { fillColor: C.card, textColor: [200, 200, 200], fontSize: 8, cellPadding: 3 },
        headStyles: { fillColor: C.lightgray, textColor: C.red, fontStyle: 'bold' },
        alternateRowStyles: { fillColor: [20, 28, 45] },
        columnStyles: { 4: { fontStyle: 'bold' } },
        margin: { left: 10, right: 10 },
        didParseCell: (data: any) => {
          if (data.column.index === 4 && data.section === 'body') {
            const sev = data.cell.raw as string;
            const [r, g, b] = sevColor(sev);
            data.cell.styles.textColor = [r, g, b];
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 8;
    }

    if (y > 200) newPage('Threat Intelligence — Geo');
    sectionHeading('Top 10 Geolocations', C.accent);
    if (topCountries.length > 0) {
      const maxReq = topCountries[0]?.count || 1;
      topCountries.slice(0, 10).forEach((c, i) => {
        hBar(`${i + 1}. ${c.name}`, c.count, maxReq, C.accent);
      });
    }
  }

  // ── Page numbers footer ─────────────────────────────────────────────────────
  const totalPages = doc.getNumberOfPages();
  for (let i = 2; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFillColor(...C.card);
    doc.rect(0, 288, W, 9, 'F');
    doc.setTextColor(...C.gray);
    doc.setFontSize(7);
    doc.text('InfiniteX WAF — Confidential Security Report', 10, 294);
    doc.text(`Page ${i} of ${totalPages}`, W - 10, 294, { align: 'right' });
  }

  const filename = `infinitex-${type}-report-${now.toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
  return filename;
}

function hexToRgb(hex: string): [number, number, number] {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return [r, g, b];
}

// ── Main Page Component ───────────────────────────────────────────────────────
export function ReportsPage() {
  const store = useDashboardStore();
  const [generating, setGenerating] = useState<ReportType | null>(null);
  const [generated, setGenerated] = useState<{ type: ReportType; filename: string; ts: string }[]>([]);

  async function generate(type: ReportType) {
    setGenerating(type);
    try {
      await store.refreshAll();
      await new Promise((r) => setTimeout(r, 400)); // let state settle
      const filename = generatePDF(type, useDashboardStore.getState());
      setGenerated((prev) => [
        { type, filename, ts: new Date().toLocaleString() },
        ...prev.slice(0, 9),
      ]);
      toast.success(`${filename} downloaded`);
    } catch (e) {
      console.error(e);
      toast.error('Failed to generate report');
    } finally {
      setGenerating(null);
    }
  }

  const { metrics } = store;
  const blockedPct = metrics.total > 0 ? ((metrics.blocked / metrics.total) * 100).toFixed(1) : '0.0';
  const riskScore  = Math.min(100, Math.round((metrics.blocked / (metrics.total || 1)) * 100 * 3 + (metrics.bot / (metrics.total || 1)) * 100));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileBarChart className="w-6 h-6 text-cyan-400" /> Reports
          </h2>
          <p className="text-gray-400 text-sm mt-1">Generate PDF security reports — executive summaries, traffic analysis, and threat intelligence</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-gray-500 bg-gray-900/50 border border-gray-800 rounded-xl px-3 py-2">
          <Clock className="w-3.5 h-3.5" />
          Data as of {new Date().toLocaleTimeString()}
        </div>
      </div>

      {/* Snapshot KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total Requests', value: metrics.total.toLocaleString(),   icon: Activity,      color: 'text-cyan-400',   bg: 'bg-cyan-500/10'   },
          { label: 'Blocked',        value: metrics.blocked.toLocaleString(), icon: Shield,        color: 'text-red-400',    bg: 'bg-red-500/10'    },
          { label: 'Block Rate',     value: `${blockedPct}%`,                 icon: TrendingUp,    color: 'text-orange-400', bg: 'bg-orange-500/10' },
          { label: 'Risk Score',     value: `${riskScore}/100`,               icon: AlertTriangle, color: riskScore > 60 ? 'text-red-400' : riskScore > 30 ? 'text-yellow-400' : 'text-green-400', bg: riskScore > 60 ? 'bg-red-500/10' : riskScore > 30 ? 'bg-yellow-500/10' : 'bg-green-500/10' },
        ].map((k) => {
          const Icon = k.icon;
          return (
            <div key={k.label} className={`${k.bg} border border-gray-800 rounded-2xl p-4 flex items-center gap-3`}>
              <Icon className={`w-8 h-8 ${k.color} shrink-0`} />
              <div>
                <p className={`text-xl font-bold ${k.color}`}>{k.value}</p>
                <p className="text-xs text-gray-500">{k.label}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Report cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {REPORT_TYPES.map((cfg) => {
          const Icon = cfg.icon;
          const isGen = generating === cfg.type;
          return (
            <div key={cfg.type} className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6 flex flex-col gap-4 hover:border-gray-700 transition-colors">
              <div className="flex items-start gap-4">
                <div className="p-3 rounded-xl bg-gray-800 shrink-0">
                  <Icon className={`w-6 h-6 ${cfg.color}`} />
                </div>
                <div className="flex-1">
                  <h3 className="text-white font-semibold">{cfg.title}</h3>
                  <p className="text-sm text-gray-400 mt-1 leading-relaxed">{cfg.description}</p>
                </div>
              </div>

              {/* Sections list */}
              <div className="flex flex-wrap gap-1.5">
                {cfg.sections.map((s) => (
                  <span key={s} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded-full">{s}</span>
                ))}
              </div>

              {/* Generate button */}
              <button
                onClick={() => generate(cfg.type)}
                disabled={isGen || generating !== null}
                className={`flex items-center justify-center gap-2 w-full py-2.5 rounded-xl text-sm font-medium transition-all ${
                  isGen
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 cursor-wait'
                    : generating !== null
                    ? 'bg-gray-800 text-gray-600 cursor-not-allowed'
                    : 'bg-cyan-500 hover:bg-cyan-600 text-white'
                }`}
              >
                {isGen ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Generating PDF…</>
                ) : (
                  <><Download className="w-4 h-4" /> Download PDF</>
                )}
              </button>
            </div>
          );
        })}
      </div>

      {/* Recent reports */}
      {generated.length > 0 && (
        <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Clock className="w-4 h-4 text-gray-400" /> Recently Generated
          </h3>
          <div className="space-y-2">
            {generated.map((g, i) => {
              const cfg = REPORT_TYPES.find((r) => r.type === g.type)!;
              const Icon = cfg.icon;
              return (
                <div key={i} className="flex items-center gap-3 py-2 border-b border-gray-800 last:border-0">
                  <Icon className={`w-4 h-4 ${cfg.color} shrink-0`} />
                  <span className="text-sm text-white flex-1 font-mono">{g.filename}</span>
                  <span className="text-xs text-gray-500">{g.ts}</span>
                  <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Info note */}
      <div className="bg-blue-500/10 border border-blue-500/20 rounded-2xl p-4 flex items-start gap-3">
        <Globe className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div className="text-sm text-blue-300">
          Reports are generated client-side using live data from the WAF. All data reflects the current state of the dashboard.
          For scheduled daily reports, configure the alert system to trigger report generation via webhook.
        </div>
      </div>
    </div>
  );
}
