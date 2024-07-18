import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css',
})
export class LoginComponent {
  username = '';
  password = '';
  protectedMessage = '';
  role = '';

  constructor(private authService: AuthService) {}

  protectedEndpoint() {
    this.authService.getProtectedEndpoint().subscribe(
      (data: any) => {
        this.protectedMessage = data.message;
        this.role = data.role;
      },
      (error) => {
        this.protectedMessage = 'Access denied';
        console.error('Error accessing protected endpoint:', error);
      },
    );
  }

  login() {
    this.authService.login(this.username, this.password);
    this.protectedEndpoint();
  }
}
