import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { HlmButton } from '@spartan-ng/helm/button';
import { AuthService } from './auth.service';
import { Documents } from './components/documents/documents';
import { Login } from './components/login/login';

@Component({
  selector: 'app-root',
  imports: [Login, Documents, HlmButton],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
})
export class AppComponent {
  readonly auth = inject(AuthService);
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly error = signal('');

  constructor() {
    void this.restoreSession();
  }

  async restoreSession(): Promise<void> {
    this.loading.set(true);
    try {
      await this.auth.restore();
    } catch (error) {
      // 401 only means "not signed in yet"; anything else is a real problem.
      if (!(error instanceof HttpErrorResponse && error.status === 401)) {
        this.error.set('Could not reach the server. Please try again.');
      }
    } finally {
      this.loading.set(false);
    }
  }

  login(): Promise<void> {
    return this.run(() => this.auth.login(), 'Sign in failed. Please try again.');
  }

  logout(): Promise<void> {
    return this.run(() => this.auth.logout(), 'Sign out failed. Please try again.');
  }

  private async run(action: () => Promise<void>, errorMessage: string): Promise<void> {
    this.busy.set(true);
    this.error.set('');
    try {
      await action();
    } catch (error) {
      // MSAL errors carry an errorCode (e.g. user_cancelled, hash_empty_error) that names the cause.
      const code = (error as { errorCode?: string })?.errorCode;
      console.error(errorMessage, code ?? '', error);
      this.error.set(code ? `${errorMessage} (${code})` : errorMessage);
    } finally {
      this.busy.set(false);
    }
  }
}
