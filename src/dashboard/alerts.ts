/**
 * InfiniteX Alert System
 * Real-time alerting with email notifications
 */

import { AdvancedWAFResult } from '../core/engine-advanced';

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  type: 'rate_limit' | 'threat' | 'ddos' | 'bot' | 'error_rate' | 'custom';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  // Thresholds
  threshold: number;
  timeWindow: number; // seconds
  consecutiveCount?: number;

  // Filters
  conditions?: {
    ruleId?: string[];
    country?: string[];
    ip?: string[];
    userAgent?: string[];
  };

  // Notification
  emailRecipients: string[];
  emailSubject?: string;
  emailTemplate?: string;

  // Cooldown
  cooldownMinutes: number;
  lastTriggered?: Date;

  // Aggregation
  aggregateBy?: 'minute' | 'hour' | 'day';
}

export interface AlertEvent {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: string;
  timestamp: Date;
  message: string;
  details: {
    threshold: number;
    actualValue: number;
    timeWindow: number;
    sampleRequests?: any[];
    affectedIPs?: string[];
    countries?: string[];
  };
  resolved: boolean;
  resolvedAt?: Date;
}

interface AlertState {
  triggered: number;
  lastTrigger?: Date;
  consecutiveTriggers: number;
}

export class AlertManager {
  private rules: AlertRule[] = [];
  private alertHistory: AlertEvent[] = [];
  private alertStates = new Map<string, AlertState>();
  private requestBuffer: { timestamp: Date; result: AdvancedWAFResult; request: any }[] = [];
  private checkInterval?: NodeJS.Timeout;
  private emailSender?: EmailSender;

  constructor() {
    this.startMonitoring();
  }

  /**
   * Set email sender
   */
  public setEmailSender(sender: EmailSender): void {
    this.emailSender = sender;
  }

  /**
   * Add or update alert rule
   */
  public addRule(rule: AlertRule): void {
    const existing = this.rules.find((r) => r.id === rule.id);
    if (existing) {
      Object.assign(existing, rule);
    } else {
      this.rules.push(rule);
    }
  }

  /**
   * Remove alert rule
   */
  public removeRule(ruleId: string): void {
    this.rules = this.rules.filter((r) => r.id !== ruleId);
    this.alertStates.delete(ruleId);
  }

  /**
   * Get all rules
   */
  public getRules(): AlertRule[] {
    return [...this.rules];
  }

  /**
   * Get alert history
   */
  public getAlertHistory(limit: number = 100): AlertEvent[] {
    return this.alertHistory.slice(-limit).reverse();
  }

  /**
   * Process request for alerting
   */
  public processRequest(request: any, result: AdvancedWAFResult): void {
    this.requestBuffer.push({
      timestamp: new Date(),
      result,
      request,
    });

    // Keep only last hour of data
    const cutoff = new Date(Date.now() - 3600000);
    this.requestBuffer = this.requestBuffer.filter((r) => r.timestamp > cutoff);
  }

  /**
   * Start monitoring
   */
  private startMonitoring(): void {
    this.checkInterval = setInterval(() => {
      this.evaluateRules();
    }, 30000); // Check every 30 seconds
  }

  /**
   * Stop monitoring
   */
  public stopMonitoring(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }
  }

  /**
   * Evaluate all rules
   */
  private evaluateRules(): void {
    const now = new Date();

    for (const rule of this.rules) {
      if (!rule.enabled) continue;

      // Check cooldown
      if (rule.lastTriggered) {
        const cooldownMs = rule.cooldownMinutes * 60000;
        if (now.getTime() - rule.lastTriggered.getTime() < cooldownMs) {
          continue;
        }
      }

      const state = this.alertStates.get(rule.id) || {
        triggered: 0,
        consecutiveTriggers: 0,
      };

      const triggered = this.evaluateRule(rule);

      if (triggered) {
        state.consecutiveTriggers++;

        // Check consecutive count requirement
        if (
          rule.consecutiveCount &&
          state.consecutiveTriggers < rule.consecutiveCount
        ) {
          continue;
        }

        this.triggerAlert(rule, state);
      } else {
        state.consecutiveTriggers = 0;
      }

      this.alertStates.set(rule.id, state);
    }
  }

  /**
   * Evaluate a single rule
   */
  private evaluateRule(rule: AlertRule): boolean {
    const windowStart = new Date(Date.now() - rule.timeWindow * 1000);
    const relevantRequests = this.requestBuffer.filter(
      (r) => r.timestamp >= windowStart
    );

    switch (rule.type) {
      case 'rate_limit':
        return relevantRequests.length > rule.threshold;

      case 'threat':
        const threats = relevantRequests.filter(
          (r) => !r.result.allowed && r.result.threatScore && r.result.threatScore > 50
        );
        return threats.length > rule.threshold;

      case 'ddos':
        const ddosEvents = relevantRequests.filter((r) =>
          r.result.reasons?.some((reason) => reason.includes('DDOS'))
        );
        return ddosEvents.length > rule.threshold;

      case 'bot':
        const botEvents = relevantRequests.filter((r) =>
          r.result.reasons?.some((reason) => reason.includes('BOT'))
        );
        return botEvents.length > rule.threshold;

      case 'error_rate':
        const blocked = relevantRequests.filter((r) => !r.result.allowed);
        const errorRate = relevantRequests.length > 0 ? blocked.length / relevantRequests.length : 0;
        return errorRate * 100 > rule.threshold;

      case 'custom':
        return this.evaluateCustomRule(rule, relevantRequests);

      default:
        return false;
    }
  }

  /**
   * Evaluate custom rule with conditions
   */
  private evaluateCustomRule(
    rule: AlertRule,
    requests: { timestamp: Date; result: AdvancedWAFResult; request: any }[]
  ): boolean {
    if (!rule.conditions) return false;

    const matches = requests.filter((r) => {
      // Check rule IDs
      if (
        rule.conditions?.ruleId?.length &&
        !rule.conditions.ruleId.includes(r.result.ruleId || '')
      ) {
        return false;
      }

      // Check countries
      if (
        rule.conditions?.country?.length &&
        !rule.conditions.country.includes(r.result.geoCountry || '')
      ) {
        return false;
      }

      // Check IPs
      if (
        rule.conditions?.ip?.length &&
        !rule.conditions.ip.includes(r.request.clientIp)
      ) {
        return false;
      }

      return true;
    });

    return matches.length > rule.threshold;
  }

  /**
   * Trigger an alert
   */
  private triggerAlert(rule: AlertRule, state: AlertState): void {
    const now = new Date();
    rule.lastTriggered = now;
    state.triggered++;
    state.lastTrigger = now;

    // Calculate actual value
    const windowStart = new Date(Date.now() - rule.timeWindow * 1000);
    const relevantRequests = this.requestBuffer.filter(
      (r) => r.timestamp >= windowStart
    );

    const alertEvent: AlertEvent = {
      id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      timestamp: now,
      message: this.generateAlertMessage(rule, relevantRequests.length),
      details: {
        threshold: rule.threshold,
        actualValue: relevantRequests.length,
        timeWindow: rule.timeWindow,
        sampleRequests: relevantRequests.slice(0, 5).map((r) => ({
          ip: r.request.clientIp,
          timestamp: r.timestamp,
          action: r.result.action,
        })),
      },
      resolved: false,
    };

    this.alertHistory.push(alertEvent);

    // Send email notification
    if (this.emailSender && rule.emailRecipients.length > 0) {
      this.sendEmailNotification(rule, alertEvent);
    }

    console.log(
      `[InfiniteX] ALERT: ${rule.name} (${rule.severity}) - ${alertEvent.message}`
    );
  }

  /**
   * Generate alert message
   */
  private generateAlertMessage(rule: AlertRule, actualValue: number): string {
    const templates: Record<string, string> = {
      rate_limit: `Request rate exceeded threshold: ${actualValue} requests in ${rule.timeWindow}s`,
      threat: `High threat activity detected: ${actualValue} blocked requests`,
      ddos: `Potential DDoS attack: ${actualValue} suspicious requests`,
      bot: `Bot traffic spike: ${actualValue} bot requests detected`,
      error_rate: `Error rate exceeded: ${actualValue}% of requests blocked`,
      custom: `Custom rule triggered: ${actualValue} matching requests`,
    };

    return templates[rule.type] || `Alert ${rule.name} triggered`;
  }

  /**
   * Send email notification
   */
  private async sendEmailNotification(
    rule: AlertRule,
    event: AlertEvent
  ): Promise<void> {
    if (!this.emailSender) return;

    const subject =
      rule.emailSubject || `[InfiniteX Alert] ${rule.name} - ${rule.severity}`;

    const html = this.generateEmailTemplate(rule, event);

    try {
      await this.emailSender.send({
        to: rule.emailRecipients,
        subject,
        html,
        text: event.message,
      });
      console.log(`[InfiniteX] Alert email sent to ${rule.emailRecipients.join(', ')}`);
    } catch (error) {
      console.error('[InfiniteX] Failed to send alert email:', error);
    }
  }

  /**
   * Generate email template
   */
  private generateEmailTemplate(rule: AlertRule, event: AlertEvent): string {
    const severityColors: Record<string, string> = {
      LOW: '#10b981',
      MEDIUM: '#f59e0b',
      HIGH: '#ef4444',
      CRITICAL: '#dc2626',
    };

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; background: #f3f4f6; padding: 20px; }
          .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; }
          .header { background: ${severityColors[event.severity]}; color: white; padding: 20px; }
          .content { padding: 20px; }
          .footer { background: #f9fafb; padding: 15px; text-align: center; color: #6b7280; font-size: 12px; }
          .stat { display: inline-block; margin: 10px; padding: 10px; background: #f3f4f6; border-radius: 4px; }
          .alert-box { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 15px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🛡️ InfiniteX Security Alert</h1>
            <p>Severity: ${event.severity}</p>
          </div>
          <div class="content">
            <h2>${rule.name}</h2>
            <p>${event.message}</p>

            <div class="alert-box">
              <strong>Alert Details:</strong><br>
              Threshold: ${event.details.threshold}<br>
              Actual Value: ${event.details.actualValue}<br>
              Time Window: ${event.details.timeWindow} seconds<br>
              Timestamp: ${event.timestamp.toISOString()}
            </div>

            <h3>Sample Affected Requests:</h3>
            ${event.details.sampleRequests
              ?.map(
                (r) => `
              <div class="stat">
                IP: ${r.ip}<br>
                Time: ${new Date(r.timestamp).toLocaleTimeString()}<br>
                Action: ${r.action}
              </div>
            `
              )
              .join('')}
          </div>
          <div class="footer">
            <p>InfiniteX WAF - Protecting your applications</p>
            <p>Alert ID: ${event.id}</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}

export interface EmailMessage {
  to: string[];
  subject: string;
  html: string;
  text: string;
}

export interface EmailSender {
  send(message: EmailMessage): Promise<void>;
}

// Example SMTP sender (would need nodemailer installed)
export class SMTPEmailSender implements EmailSender {
  private transporter: any;

  constructor(config: {
    host: string;
    port: number;
    secure: boolean;
    auth: { user: string; pass: string };
  }) {
    // const nodemailer = require('nodemailer');
    // this.transporter = nodemailer.createTransport(config);
  }

  async send(message: EmailMessage): Promise<void> {
    // await this.transporter.sendMail({
    //   from: '"InfiniteX WAF" <alerts@infinitex.io>',
    //   to: message.to.join(', '),
    //   subject: message.subject,
    //   text: message.text,
    //   html: message.html,
    // });
    console.log(`[Email] Would send to ${message.to.join(', ')}: ${message.subject}`);
  }
}

// Singleton instance
export const alertManager = new AlertManager();
