import { Component, input, output } from '@angular/core';
import { HlmButton } from '@spartan-ng/helm/button';
import { HlmCard } from '@spartan-ng/helm/card';

@Component({
  selector: 'app-login',
  imports: [HlmButton, HlmCard],
  templateUrl: './login.html',
  styleUrl: './login.css',
})
export class Login {
  readonly busy = input(false);
  readonly signIn = output<void>();
}
