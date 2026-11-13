import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, firstValueFrom, timeout } from 'rxjs';

export interface Credentials {
  email: string;
  password: string;
}

export interface User {
  email: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly currentUser = signal<User | null>(null);
  readonly user = this.currentUser.asReadonly();

  async restore(): Promise<void> {
    await this.loadUser(this.http.get<User>('/api/auth/session'));
  }

  async login(credentials: Credentials): Promise<void> {
    await this.loadUser(this.http.post<User>('/api/auth/login', credentials));
  }

  async logout(): Promise<void> {
    await firstValueFrom(this.http.post<void>('/api/auth/logout', {}).pipe(timeout(10000)));
    this.clear();
  }

  clear(): void {
    this.currentUser.set(null);
  }

  private async loadUser(request: Observable<User>): Promise<void> {
    const user = await firstValueFrom(request.pipe(timeout(10000)));
    if (!user || typeof user.email !== 'string' || !user.email.trim()) {
      throw new Error('Invalid session response');
    }
    this.currentUser.set(user);
  }
}
