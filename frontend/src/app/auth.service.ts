import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { PublicClientApplication } from '@azure/msal-browser';
import { firstValueFrom } from 'rxjs';

export interface User {
  email: string;
}

interface AuthConfig {
  clientId: string;
  authority: string;
  scope: string;
  redirectUri: string;
}

/**
 * Login flow: Microsoft popup login -> access token -> POST /api/auth/login
 * -> the server answers with a session cookie that the browser sends automatically.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly currentUser = signal<User | null>(null);
  readonly user = this.currentUser.asReadonly();
  private config?: AuthConfig;
  private msal?: PublicClientApplication;

  /** Asks the server whether the session cookie is still valid (e.g. after a page reload). */
  async restore(): Promise<void> {
    await this.loadConfig();
    this.currentUser.set(await firstValueFrom(this.http.get<User>('/api/auth/session')));
  }

  async login(): Promise<void> {
    const { config, msal } = await this.loadConfig();
    const result = await msal.loginPopup({ scopes: [config.scope], prompt: 'select_account' });
    const headers = { Authorization: `Bearer ${result.accessToken}` };
    this.currentUser.set(await firstValueFrom(this.http.post<User>('/api/auth/login', {}, { headers })));
    // The Microsoft token is only needed once, so it is not kept in the browser.
    await msal.clearCache();
  }

  async logout(): Promise<void> {
    await firstValueFrom(this.http.post<void>('/api/auth/logout', {}));
    this.clear();
  }

  clear(): void {
    this.currentUser.set(null);
  }

  private async loadConfig(): Promise<{ config: AuthConfig; msal: PublicClientApplication }> {
    if (!this.config || !this.msal) {
      const config = await firstValueFrom(this.http.get<AuthConfig>('/api/auth/config'));
      const msal = new PublicClientApplication({
        auth: { clientId: config.clientId, authority: config.authority, redirectUri: config.redirectUri },
        cache: { cacheLocation: 'memoryStorage' },
      });
      await msal.initialize();
      this.config = config;
      this.msal = msal;
    }
    return { config: this.config, msal: this.msal };
  }
}
