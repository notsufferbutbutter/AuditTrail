import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { AuditDashboard } from './audit-dashboard';

describe('AuditDashboard', () => {
  let fixture: ComponentFixture<AuditDashboard>;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AuditDashboard],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(AuditDashboard);
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  function expectDashboardRequests() {
    const events = http.expectOne('/v1/events?limit=50');
    const alerts = http.expectOne('/v1/alerts?limit=50');
    return { events, alerts };
  }

  it('loads and displays events and alerts', async () => {
    const { events, alerts } = expectDashboardRequests();
    events.flush([
      {
        id: 'event-1',
        event_id: 'evt-001',
        application_id: 'application-1',
        environment: 'dev',
        service_id: 'service-1',
        action: 'user.login',
        outcome: 'failure',
        actor: { type: 'user', id: 'user-123' },
        occurred_at: '2026-11-27T00:00:00Z',
        received_at: '2026-11-27T00:01:00Z',
      },
    ]);
    alerts.flush([
      {
        id: 'alert-1',
        application_id: 'application-1',
        environment: 'dev',
        service_id: 'service-1',
        rule_code: 'repeated_login_failures',
        actor_id: 'user-123',
        severity: 'high',
        status: 'open',
        title: 'Repeated login failures',
        failure_count: 5,
        last_seen_at: '2026-11-27T00:01:00Z',
      },
    ]);

    await fixture.whenStable();
    fixture.detectChanges();

    const text = fixture.nativeElement.textContent;
    expect(text).toContain('user.login');
    expect(text).toContain('user-123');
    expect(text).toContain('Repeated login failures');
    expect(text).toContain('failure');
  });

  it('shows empty states when the API returns no records', async () => {
    const { events, alerts } = expectDashboardRequests();
    events.flush([]);
    alerts.flush([]);

    await fixture.whenStable();
    fixture.detectChanges();

    expect(fixture.nativeElement.textContent).toContain('No alerts to show.');
    expect(fixture.nativeElement.textContent).toContain('No events to show yet.');
  });

  it('shows an explicit message when audit storage is unavailable', async () => {
    const { events, alerts } = expectDashboardRequests();
    events.flush(
      { detail: 'Audit storage is unavailable' },
      { status: 503, statusText: 'Service Unavailable' },
    );
    alerts.flush([]);

    await fixture.whenStable();
    fixture.detectChanges();

    expect(fixture.nativeElement.textContent).toContain('Audit storage is unavailable.');
  });
});
