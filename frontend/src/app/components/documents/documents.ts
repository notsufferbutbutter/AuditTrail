import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Component, effect, inject, signal } from '@angular/core';
import { HlmButton } from '@spartan-ng/helm/button';
import { HlmCard } from '@spartan-ng/helm/card';
import { firstValueFrom } from 'rxjs';
import { AuthService } from '../../auth.service';

interface AuditDocument {
  id: string;
  name: string;
}

/** Calls the protected GET /api/documents endpoint and shows the result. */
@Component({
  selector: 'app-documents',
  imports: [HlmButton, HlmCard],
  templateUrl: './documents.html',
  styleUrl: './documents.css',
})
export class Documents {
  private readonly http = inject(HttpClient);
  readonly auth = inject(AuthService);
  readonly documents = signal<AuditDocument[]>([]);
  readonly message = signal('');
  readonly granted = signal(false);

  constructor() {
    // Forget the old result whenever someone signs in or out.
    effect(() => {
      this.auth.user();
      this.documents.set([]);
      this.message.set('');
    });
  }

  async load(): Promise<void> {
    try {
      const documents = await firstValueFrom(this.http.get<AuditDocument[]>('/api/documents'));
      this.documents.set(documents);
      this.granted.set(true);
      this.message.set(`Access granted: ${documents.length} document(s).`);
    } catch (error) {
      this.documents.set([]);
      this.granted.set(false);
      if (error instanceof HttpErrorResponse && error.status === 401) {
        this.message.set('Access denied (401): please sign in.');
      } else {
        this.message.set('The request failed. Please try again.');
      }
    }
  }
}
