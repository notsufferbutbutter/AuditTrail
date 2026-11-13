import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { AppComponent } from './app.component';

describe('Authentication and document access', () => {
  let fixture: ComponentFixture<AppComponent>;
  let app: AppComponent;
  let http: HttpTestingController;
  const credentials = { email: 'admin@example.com', password: 'test-password' };
  const user = { email: credentials.email };

  beforeEach(async () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(AppComponent);
    app = fixture.componentInstance;
    http.expectOne('/api/auth/session').flush(null, { status: 401, statusText: 'Unauthorized' });
    await fixture.whenStable();
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  async function login(): Promise<void> {
    const pending = app.login(credentials);
    const request = http.expectOne('/api/auth/login');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual(credentials);
    request.flush(user);
    await pending;
    fixture.detectChanges();
  }

  it('shows editable, empty login fields for a signed-out user', () => {
    const email = fixture.nativeElement.querySelector('#login-email') as HTMLInputElement;
    expect(email.value).toBe('');
    expect(email.readOnly).toBe(false);
    expect(app.auth.user()).toBeNull();
  });

  it('submits the login form and shows the authenticated user', async () => {
    for (const [name, value] of Object.entries(credentials)) {
      const input = fixture.nativeElement.querySelector(`[name="${name}"]`) as HTMLInputElement;
      input.value = value;
      input.dispatchEvent(new Event('input'));
    }
    await fixture.whenStable();
    fixture.detectChanges();
    fixture.nativeElement.querySelector('form').dispatchEvent(new Event('submit', { cancelable: true }));
    const request = http.expectOne('/api/auth/login');
    expect(request.request.body).toEqual(credentials);
    request.flush(user);
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('app-login')).toBeNull();
    expect(fixture.nativeElement.textContent).toContain(user.email);
    expect(fixture.nativeElement.textContent).toContain('Sign out');
  });

  it('keeps the user signed out when credentials are rejected', async () => {
    const pending = app.login(credentials);
    http.expectOne('/api/auth/login').flush(null, { status: 401, statusText: 'Unauthorized' });
    await pending;
    expect(app.auth.user()).toBeNull();
    expect(app.error()).toBe('Incorrect email or password.');
  });

  it('explains login throttling without granting access', async () => {
    const pending = app.login(credentials);
    http.expectOne('/api/auth/login').flush(null, { status: 429, statusText: 'Too Many Requests' });
    await pending;
    expect(app.auth.user()).toBeNull();
    expect(app.error()).toContain('Too many sign-in attempts');
  });

  it('reports unavailable authentication endpoints without granting access', async () => {
    const pending = app.login(credentials);
    http.expectOne('/api/auth/login').flush(null, { status: 503, statusText: 'Unavailable' });
    await pending;
    expect(app.auth.user()).toBeNull();
    expect(app.error()).toContain('Sign in failed');
    expect(app.busy()).toBeNull();
  });

  it('does not treat a malformed login response as an authenticated session', async () => {
    const pending = app.login(credentials);
    http.expectOne('/api/auth/login').flush({ status: 'OK' });
    await pending;
    expect(app.auth.user()).toBeNull();
    expect(app.error()).toContain('Sign in failed');
  });

  it('restores a server session after a reload', async () => {
    const pending = app.restoreSession();
    http.expectOne('/api/auth/session').flush(user);
    await pending;
    expect(app.auth.user()).toEqual(user);
  });

  it('rejects document access before login and after logout, and allows it during a session', async () => {
    let pending = app.checkDocuments();
    http.expectOne('/api/documents').flush(null, { status: 401, statusText: 'Unauthorized' });
    await pending;
    expect(app.documentState()).toBe('denied');

    await login();
    pending = app.checkDocuments();
    http.expectOne('/api/documents').flush([{ id: '1', name: 'Report.pdf' }]);
    await pending;
    fixture.detectChanges();
    expect(app.documentState()).toBe('success');
    expect(fixture.nativeElement.textContent).toContain('Report.pdf');

    pending = app.logout();
    const logout = http.expectOne('/api/auth/logout');
    expect(logout.request.method).toBe('POST');
    logout.flush(null, { status: 204, statusText: 'No Content' });
    await pending;
    expect(app.auth.user()).toBeNull();
    expect(app.documents()).toEqual([]);

    pending = app.checkDocuments();
    http.expectOne('/api/documents').flush(null, { status: 401, statusText: 'Unauthorized' });
    await pending;
    expect(app.documentState()).toBe('denied');
  });

  it('reports a protection failure if documents are public', async () => {
    const pending = app.checkDocuments();
    http.expectOne('/api/documents').flush([]);
    await pending;
    expect(app.documentState()).toBe('error');
    expect(app.documentMessage()).toContain('Protection failed');
  });

  it('clears a session when the document endpoint returns 401', async () => {
    await login();
    const pending = app.checkDocuments();
    http.expectOne('/api/documents').flush(null, { status: 401, statusText: 'Unauthorized' });
    await pending;
    expect(app.auth.user()).toBeNull();
    expect(app.documents()).toEqual([]);
    expect(app.documentState()).toBe('denied');
  });

  it('reports a permission failure without treating 403 as a logout', async () => {
    await login();
    const pending = app.checkDocuments();
    http.expectOne('/api/documents').flush(null, { status: 403, statusText: 'Forbidden' });
    await pending;
    expect(app.auth.user()).toEqual(user);
    expect(app.documentState()).toBe('denied');
  });

  it('keeps the session visible if logout fails so the user can retry', async () => {
    await login();
    const pending = app.logout();
    http.expectOne('/api/auth/logout').flush(null, { status: 503, statusText: 'Unavailable' });
    await pending;
    expect(app.auth.user()).toEqual(user);
    expect(app.error()).toContain('Sign out failed');
  });

  it('treats a rejected logout as an already expired session', async () => {
    await login();
    const pending = app.logout();
    http.expectOne('/api/auth/logout').flush(null, { status: 401, statusText: 'Unauthorized' });
    await pending;
    expect(app.auth.user()).toBeNull();
    expect(app.error()).toBe('');
  });

  it('does not mistake an HTML fallback or malformed response for document access', async () => {
    await login();
    const pending = app.checkDocuments();
    http.expectOne('/api/documents').flush({ status: 'OK' });
    await pending;
    expect(app.documentState()).toBe('error');
  });

  it('prevents overlapping authentication requests', async () => {
    const first = app.login(credentials);
    const second = app.login(credentials);
    http.expectOne('/api/auth/login').flush(user);
    await Promise.all([first, second]);
    expect(app.busy()).toBeNull();
  });

  it('times out stalled requests and allows retrying', async () => {
    vi.useFakeTimers();
    try {
      const pending = app.checkDocuments();
      const request = http.expectOne('/api/documents');
      await vi.advanceTimersByTimeAsync(10001);
      await pending;
      expect(request.cancelled).toBe(true);
      expect(app.documentState()).toBe('error');
      expect(app.busy()).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
