import { Component, input, output } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HlmButton } from '@spartan-ng/helm/button';
import { HlmCard } from '@spartan-ng/helm/card';
import { HlmInput } from '@spartan-ng/helm/input';
import { HlmLabel } from '@spartan-ng/helm/label';
import { Credentials } from '../../auth.service';

@Component({
  selector: 'app-login',
  imports: [FormsModule, HlmButton, HlmCard, HlmInput, HlmLabel],
  templateUrl: './login.html',
  styleUrl: './login.css',
})
export class Login {
  readonly busy = input(false);
  readonly signIn = output<Credentials>();
  email = '';
  password = '';

  submit(): void {
    if (this.busy()) return;
    this.signIn.emit({ email: this.email.trim(), password: this.password });
    this.password = '';
  }
}
