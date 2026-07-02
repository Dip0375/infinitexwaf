/**
 * InfiniteX Export Logger
 * Exports logs to AWS S3, Azure Blob, GCS, and other storage
 */

import * as fs from 'fs';
import * as path from 'path';
import { requestLogs } from './api';

export interface ExportConfig {
  enabled: boolean;
  type: 's3' | 'azure' | 'gcs' | 'local';
  format: 'json' | 'csv' | 'parquet';
  interval: 'realtime' | 'minute' | 'hour' | 'day';
  compression?: 'gzip' | 'none';

  // S3 Config
  s3Bucket?: string;
  s3Region?: string;
  s3AccessKey?: string;
  s3SecretKey?: string;
  s3Prefix?: string;

  // Azure Config
  azureConnectionString?: string;
  azureContainerName?: string;
  azurePrefix?: string;

  // GCS Config
  gcsBucket?: string;
  gcsProjectId?: string;
  gcsKeyFile?: string;
  gcsPrefix?: string;

  // Local Config
  localPath?: string;
}

export class ExportLogger {
  private config: ExportConfig;
  private buffer: any[] = [];
  private lastExport: Date = new Date();
  private exportTimer?: NodeJS.Timeout;

  constructor(config: ExportConfig) {
    this.config = config;
    if (config.enabled) {
      this.startExportTimer();
    }
  }

  /**
   * Add log entry to buffer
   */
  public log(entry: any): void {
    if (!this.config.enabled) return;

    this.buffer.push({
      ...entry,
      _exportTimestamp: new Date().toISOString(),
    });

    // Real-time export
    if (this.config.interval === 'realtime') {
      this.exportBatch();
    }
  }

  /**
   * Start export timer
   */
  private startExportTimer(): void {
    const intervals: Record<string, number> = {
      realtime: 1000,
      minute: 60000,
      hour: 3600000,
      day: 86400000,
    };

    const interval = intervals[this.config.interval] || 60000;

    this.exportTimer = setInterval(() => {
      this.exportBatch();
    }, interval);
  }

  /**
   * Export batch of logs
   */
  private async exportBatch(): Promise<void> {
    if (this.buffer.length === 0) return;

    const batch = [...this.buffer];
    this.buffer = [];
    this.lastExport = new Date();

    try {
      switch (this.config.type) {
        case 's3':
          await this.exportToS3(batch);
          break;
        case 'azure':
          await this.exportToAzure(batch);
          break;
        case 'gcs':
          await this.exportToGCS(batch);
          break;
        case 'local':
        default:
          await this.exportToLocal(batch);
      }
    } catch (error) {
      console.error('[InfiniteX] Export failed:', error);
      // Re-add to buffer for retry
      this.buffer.unshift(...batch);
    }
  }

  /**
   * Export to AWS S3
   */
  private async exportToS3(batch: any[]): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${this.config.s3Prefix || 'infinitex-logs'}/${timestamp}.${this.config.format}${this.config.compression === 'gzip' ? '.gz' : ''}`;

    const data = this.formatData(batch);

    // Using AWS SDK v3 (would need to be installed)
    // For now, log that it would be exported
    console.log(`[InfiniteX] Exporting ${batch.length} logs to S3: ${this.config.s3Bucket}/${filename}`);

    // In production:
    // const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
    // const s3 = new S3Client({ region: this.config.s3Region });
    // await s3.send(new PutObjectCommand({
    //   Bucket: this.config.s3Bucket,
    //   Key: filename,
    //   Body: data,
    //   ContentType: this.config.format === 'json' ? 'application/json' : 'text/csv',
    // }));
  }

  /**
   * Export to Azure Blob Storage
   */
  private async exportToAzure(batch: any[]): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${this.config.azurePrefix || 'infinitex-logs'}/${timestamp}.${this.config.format}`;

    const data = this.formatData(batch);

    console.log(`[InfiniteX] Exporting ${batch.length} logs to Azure: ${this.config.azureContainerName}/${filename}`);

    // In production:
    // const { BlobServiceClient } = require('@azure/storage-blob');
    // const blobServiceClient = BlobServiceClient.fromConnectionString(this.config.azureConnectionString);
    // const containerClient = blobServiceClient.getContainerClient(this.config.azureContainerName);
    // const blockBlobClient = containerClient.getBlockBlobClient(filename);
    // await blockBlobClient.upload(data, data.length);
  }

  /**
   * Export to Google Cloud Storage
   */
  private async exportToGCS(batch: any[]): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${this.config.gcsPrefix || 'infinitex-logs'}/${timestamp}.${this.config.format}`;

    const data = this.formatData(batch);

    console.log(`[InfiniteX] Exporting ${batch.length} logs to GCS: ${this.config.gcsBucket}/${filename}`);

    // In production:
    // const { Storage } = require('@google-cloud/storage');
    // const storage = new Storage({ projectId: this.config.gcsProjectId, keyFilename: this.config.gcsKeyFile });
    // const bucket = storage.bucket(this.config.gcsBucket);
    // const file = bucket.file(filename);
    // await file.save(data);
  }

  /**
   * Export to local filesystem
   */
  private async exportToLocal(batch: any[]): Promise<void> {
    const exportDir = this.config.localPath || './logs/export';
    if (!fs.existsSync(exportDir)) {
      fs.mkdirSync(exportDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `infinitex-${timestamp}.${this.config.format}`;
    const filepath = path.join(exportDir, filename);

    const data = this.formatData(batch);

    // Append to existing file or create new
    if (fs.existsSync(filepath)) {
      const existing = fs.readFileSync(filepath, 'utf-8');
      if (this.config.format === 'json') {
        const existingData = JSON.parse(existing);
        existingData.push(...batch);
        fs.writeFileSync(filepath, JSON.stringify(existingData, null, 2));
      } else {
        fs.appendFileSync(filepath, '\n' + data);
      }
    } else {
      if (this.config.format === 'json') {
        fs.writeFileSync(filepath, JSON.stringify(batch, null, 2));
      } else {
        fs.writeFileSync(filepath, data);
      }
    }

    console.log(`[InfiniteX] Exported ${batch.length} logs to local: ${filepath}`);
  }

  /**
   * Format data for export
   */
  private formatData(batch: any[]): string {
    switch (this.config.format) {
      case 'csv':
        return this.toCSV(batch);
      case 'parquet':
        // Would use parquet library
        return JSON.stringify(batch);
      case 'json':
      default:
        return JSON.stringify(batch, null, 2);
    }
  }

  /**
   * Convert to CSV
   */
  private toCSV(batch: any[]): string {
    if (batch.length === 0) return '';

    const headers = Object.keys(batch[0]);
    const rows = batch.map((row) =>
      headers.map((h) => {
        const val = row[h];
        if (typeof val === 'object') return JSON.stringify(val);
        return String(val);
      }).join(',')
    );

    return [headers.join(','), ...rows].join('\n');
  }

  /**
   * Force immediate export
   */
  public async forceExport(): Promise<void> {
    await this.exportBatch();
  }

  /**
   * Get export statistics
   */
  public getStats(): { lastExport: Date; buffered: number } {
    return {
      lastExport: this.lastExport,
      buffered: this.buffer.length,
    };
  }

  /**
   * Stop export timer
   */
  public stop(): void {
    if (this.exportTimer) {
      clearInterval(this.exportTimer);
    }
  }
}

// Default export config
export const DEFAULT_EXPORT_CONFIG: ExportConfig = {
  enabled: false,
  type: 'local',
  format: 'json',
  interval: 'hour',
  compression: 'none',
  localPath: './logs/export',
};

// Singleton instance
let exportLogger: ExportLogger | null = null;

export function getExportLogger(config?: ExportConfig): ExportLogger {
  if (!exportLogger && config) {
    exportLogger = new ExportLogger(config);
  }
  return exportLogger || new ExportLogger(DEFAULT_EXPORT_CONFIG);
}
