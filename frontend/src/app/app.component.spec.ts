import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { AppComponent } from './app.component';
import { AuthService, User } from './auth.service';

// The real AuthService opens a Microsoft popup, so the tests use a simple stand-in.
class FakeAuthService {
  readonly user = signal<User | null>(null);
  signedInUser: User | null = null; // what the server's session check "returns"
  restore = async () => {
    this.user.set(this.signedInUser);
    if (!this.signedInUser) throw Object.assign(new Error(), { status: 401 });
  };
  login = async () => this.user.set({ email: 'person@example.com' });
  logout = async () => this.user.set(null);
}

describe('Login, logout and document access', () => {
  let fixture: ComponentFixture<AppComponent>;
  let auth: FakeAuthService;
  let http: HttpTestingController;

  async function start(signedInUser: User | null) {
    auth = TestBed.inject(AuthService) as unknown as FakeAuthService;
    auth.signedInUser = signedInUser;
    fixture = TestBed.createComponent(AppComponent);
    await fixture.whenStable();
    fixture.detectChanges();
  }

  function click(text: string) {
    const buttons: HTMLButtonElement[] = Array.from(fixture.nativeElement.querySelectorAll('button'));
    buttons.find(button => button.textContent?.includes(text))!.click();
  }

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: AuthService, useClass: FakeAuthService },
      ],
    });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('shows the login button when nobody is signed in', async () => {
    await start(null);
    expect(fixture.nativeElement.textContent).toContain('Sign in with Microsoft');
  });

  it('shows the user and a sign out button after login', async () => {
    await start(null);
    click('Sign in with Microsoft');
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('person@example.com');
    expect(fixture.nativeElement.textContent).toContain('Sign out');
  });

  it('shows the login button again after logout', async () => {
    await start({ email: 'person@example.com' });
    click('Sign out');
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Sign in with Microsoft');
  });

  it('reports "access denied" when the server answers 401', async () => {
    await start(null);
    click('Test protected endpoint');
    http.expectOne('/api/documents').flush(null, { status: 401, statusText: 'Unauthorized' });
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Access denied (401)');
  });

  it('shows the documents when the server answers 200', async () => {
    await start({ email: 'person@example.com' });
    click('Load documents');
    http.expectOne('/api/documents').flush([{ id: '1', name: 'Report.pdf' }]);
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Access granted: 1 document(s).');
    expect(fixture.nativeElement.textContent).toContain('Report.pdf');
  });
});
