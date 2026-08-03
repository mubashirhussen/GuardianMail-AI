export interface User {
  id: string;
  email: string;
  username: string;
  full_name: string;
  role: 'admin' | 'soc_analyst' | 'security_analyst' | 'user';
  is_active: boolean;
  mfa_enabled?: boolean;
}

export interface UserResponse {
  email: string;
  username: string;
  full_name: string;
  role: string;
  is_active: boolean;
  id: string;
}

export interface Attachment {
  id?: string;
  filename: string;
  size_bytes: number;
  mime_type?: string;
  is_malicious?: boolean;
  ocr_content?: string;
}

export interface EmailHeaders {
  received?: string[];
  spf?: string;
  dkim?: string;
  dmarc?: string;
  [key: string]: any;
}

export interface Indicator {
  indicator: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
  type: string;
}

export interface EmailRecord {
  id: string;
  _id?: string;
  subject: string;
  from_address: string;
  to_address: string;
  date: string;
  body_text?: string;
  body_html?: string;
  headers?: EmailHeaders;
  attachments?: Attachment[];
  urls?: Array<{ url: string; risk_score?: number }>;
  analysis?: {
    verdict: 'PHISHING' | 'MALWARE' | 'BEC' | 'SPAM' | 'SUSPICIOUS' | 'SAFE';
    risk_score: number;
    confidence_score: number;
    explanation?: string;
    indicators?: Indicator[];
    timeline?: Array<{ event: string; description: string; timestamp: string }>;
    detector_sources?: string[];
  };
  gmail_account?: string;
  body_plain?: string;
  recommendations?: {
    next_steps?: string[];
    security_tips?: string[];
  };
}

export interface TimelineEvent {
  id?: string;
  event: string;
  description: string;
  timestamp: string;
}

export interface RecoveryAction {
  _id?: string;
  id: string;
  incident_id: string;
  action_type: string;
  description: string;
  is_completed: boolean;
  completed_at?: string;
}

export interface ComplaintDraft {
  id?: string;
  _id?: string;
  incident_id: string;
  recipient_entity: string;
  template_type: string;
  subject: string;
  body: string;
  created_at: string;
  status: string;
}

export interface IncidentRecord {
  id: string;
  incident_id: string;
  status: 'Detected' | 'Under Review' | 'Investigating' | 'Evidence Generated' | 'Complaint Draft Ready' | 'User Confirmed' | 'Closed' | 'Archived';
  detection_time: string;
  threat_category: string;
  threat_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  affected_email: string;
  affected_user: string;
  related_devices?: string[];
  related_gmail_account?: string;
  related_attachments?: string[];
  related_urls?: string[];
  tags?: string[];
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  custom_labels?: Record<string, string>;
  investigation_notes?: string;
  evidence_pack_id?: string;
  complaint_draft_id?: string;
  created_at: string;
  updated_at: string;
}

export interface ReportLog {
  id: string;
  _id?: string;
  report_id: string;
  report_type: string;
  export_format: string;
  created_at: string;
  created_by: string;
}

export interface SystemHealthMetrics {
  api_gateway: string;
  mongodb: string;
  redis: string;
  celery_broker: string;
  host_metrics: {
    cpu_utilization_percent: number;
    memory_utilization_percent: number;
    disk_utilization_percent: number;
  };
  timestamp: string;
}
