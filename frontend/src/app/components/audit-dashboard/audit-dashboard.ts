import { DatePipe } from '@angular/common';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit, inject, signal } from '@angular/core';
import { HlmButton } from '@spartan-ng/helm/button';
import { HlmCard } from '@spartan-ng/helm/card';
import { firstValueFrom } from 'rxjs';

interface Actor {
  type: string;
  id: string;
}

interface AuditEvent {
  id: string;
  event_id: string;
  application_id: string;
  environment: string;
  service_id: string;
  action: string;
  outcome: 'success' | 'failure';
  actor: Actor;
  occurred_at: string;
  received_at: string;
}

interface AuditAlert {
  id: string;
  application_id: string;
  environment: string;
  service_id: string;
  rule_code: string;
  actor_id: string;
  severity: string;
  status: string;
  title: string;
  failure_count: number;
  last_seen_at: string;
}

@Component({
  selector: 'app-audit-dashboard',
  imports: [DatePipe, HlmButton, HlmCard],
  templateUrl: './audit-dashboard.html',
  styleUrl: './audit-dashboard.css',
})
export class AuditDashboard implements OnInit {
  private readonly http = inject(HttpClient);

  readonly events = signal<AuditEvent[]>([]);
  readonly alerts = signal<AuditAlert[]>([]);
  readonly loading = signal(false);
  readonly error = signal('');

  ngOnInit(): void {
    void this.refresh();
  }

  async refresh(): Promise<void> {
    this.loading.set(true);
    this.error.set('');
    this.events.set([]);
    this.alerts.set([]);

    try {
      const [events, alerts] = await Promise.all([
        firstValueFrom(this.http.get<AuditEvent[]>('/v1/events', { params: { limit: 50 } })),
        firstValueFrom(this.http.get<AuditAlert[]>('/v1/alerts', { params: { limit: 50 } })),
      ]);
      this.events.set(events);
      this.alerts.set(alerts);
    } catch (error) {
      this.error.set(this.errorMessage(error));
    } finally {
      this.loading.set(false);
    }
  }

  private errorMessage(error: unknown): string {
    if (error instanceof HttpErrorResponse && error.status === 401) {
      return 'Your session expired. Sign out and sign in again to view audit data.';
    }
    if (error instanceof HttpErrorResponse && error.status === 503) {
      return 'Audit storage is unavailable. The database may not be connected yet.';
    }
    return 'Could not load audit data. Check your connection and try again.';
  }
}
