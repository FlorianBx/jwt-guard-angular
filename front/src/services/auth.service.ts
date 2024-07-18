// src/services/auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { CookieService } from 'ngx-cookie-service';
import { jwtDecode } from "jwt-decode";

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private API_URL = 'http://localhost:3005/api';

  constructor(private http: HttpClient, private cookieService: CookieService) { }

  login(username: string, password: string) {
    return this.http.post<{ token: string }>(`${this.API_URL}/login`, { username, password })
      .subscribe(response => {
        if (response.token) {
          this.cookieService.set('jwt', response.token);
        }
      });
  }

  logout() {
    this.cookieService.delete('jwt');
  }

  getToken() {
    return this.cookieService.get('jwt');
  }

  getUserRole(): string {
    const token = this.getToken();
    if (token) {
      try {
        const decoded: any = jwtDecode(token);
        return decoded.role;
      } catch (error) {
        console.error('Invalid token');
        return '';
      }
    }
    return '';
  }

  getProtectedEndpoint() {
    return this.http.get(`${this.API_URL}/protected`);
  }
}
