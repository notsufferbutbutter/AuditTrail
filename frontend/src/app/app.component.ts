import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { HlmButton } from '@spartan-ng/helm/button';
import { HlmCard } from '@spartan-ng/helm/card';
import { firstValueFrom, timeout } from 'rxjs';
import { AuthService, Credentials } from './auth.service';
import { Login } from './components/login/login';

interface Document {
  id: string;
  name: string;
}

@Component({
  selector: 'app-root',
  imports: [Login, HlmButton, HlmCard],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
})
export class AppComponent {
  readonly auth = inject(AuthService);
  private readonly http = inject(HttpClient);
  readonly busy = signal<'session' | 'login' | 'logout' | 'documents' | null>(null);
  readonly error = signal('');
  readonly documentState = signal<'idle' | 'success' | 'denied' | 'error'>('idle');
  readonly documentMessage = signal('');
  readonly documents = signal<Document[]>([]);

  constructor() {
    void this.restoreSession();
  }

  async restoreSession(): Promise<void> {
    if (this.busy()) return;
    this.busy.set('session');
    this.error.set('');
    try {
      await this.auth.restore();
    } catch (error) {
      if (!this.unauthorized(error)) {
        this.error.set('Could not check your session. Check the server and try again.');
      }
    } finally {
      this.busy.set(null);
    }
  }

  async login(credentials: Credentials): Promise<void> {
    if (this.busy()) return;
    this.busy.set('login');
    this.error.set('');
    this.resetDocuments();
    try {
      await this.auth.login(credentials);
    } catch (error) {
      this.error.set(this.unauthorized(error)
        ? 'Incorrect email or password.'
        : error instanceof HttpErrorResponse && error.status === 429
        ? 'Too many sign-in attempts. Please wait and try again.'
        : 'Sign in failed. Check the server and try again.');
    } finally {
      this.busy.set(null);
    }
  }

  async logout(): Promise<void> {
    if (this.busy()) return;
    this.busy.set('logout');
    this.error.set('');
    try {
      await this.auth.logout();
      this.resetDocuments();
    } catch (error) {
      if (this.unauthorized(error)) {
        this.resetDocuments();
      } else {
        this.error.set('Sign out failed. Your session may still be active. Please retry.');
      }
    } finally {
      this.busy.set(null);
    }
  }

  async checkDocuments(): Promise<void> {
    if (this.busy()) return;
    const signedIn = !!this.auth.user();
    this.busy.set('documents');
    this.error.set('');
    this.resetDocuments();
    this.documentMessage.set('Calling GET /api/documents…');
    try {
      const documents = await firstValueFrom(
        this.http.get<Document[]>('/api/documents').pipe(timeout(10000)),
      );
      if (!Array.isArray(documents) || !documents.every(document =>
        document && typeof document.id === 'string' && typeof document.name === 'string')) {
        throw new Error('Invalid document response');
      }
      this.documentState.set(signedIn ? 'success' : 'error');
      this.documentMessage.set(signedIn
        ? `Access granted. ${documents.length} document(s) returned.`
        : 'Protection failed: the server allowed access without signing in.');
      if (signedIn) this.documents.set(documents);
    } catch (error) {
      const denied = this.unauthorized(error) ||
        (error instanceof HttpErrorResponse && error.status === 403);
      this.documentState.set(denied ? 'denied' : 'error');
      this.documentMessage.set(denied
        ? signedIn ? 'Access denied. Sign in again or check your permissions.' : 'Access denied. The document endpoint is protected.'
        : 'Document request failed. Check the server and try again.');
    } finally {
      this.busy.set(null);
    }
  }

  private unauthorized(error: unknown): boolean {
    if (!(error instanceof HttpErrorResponse) || error.status !== 401) return false;
    this.auth.clear();
    return true;
  }

  private resetDocuments(): void {
    this.documents.set([]);
    this.documentState.set('idle');
    this.documentMessage.set('');
  }
}
