# Guide d'Authentification avec JWT

## Introduction

Ce guide explique comment mettre en place une authentification basée sur JSON Web Tokens (JWT) dans une application Angular avec un backend Express.js. Il couvre les étapes suivantes :
1. Connexion de l'utilisateur et génération du JWT.
2. Stockage du JWT côté client.
3. Utilisation d'un intercepteur HTTP pour ajouter automatiquement le JWT aux requêtes sortantes.
4. Protection des routes avec des guards.

## 1. Connexion de l'Utilisateur et Génération du JWT

### Backend Express.js

Le serveur Express.js vérifie les identifiants de l'utilisateur, génère un JWT avec le rôle de l'utilisateur, et renvoie ce token au client.

```javascript
import express from 'express';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import cors from 'cors';

const app = express();
const PORT = 3005;
const SECRET_KEY = 'lalalalala';

app.use(bodyParser.json());
app.use(cors({ origin: 'http://localhost:4200', methods: ['GET', 'POST'], credentials: true, allowedHeaders: ['Content-Type', 'Authorization'] }));

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === 'password') {
    const token = jwt.sign({ role: 'admin' }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } else if (username === 'user' && password === 'password') {
    const token = jwt.sign({ role: 'user' }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

app.get('/api/protected', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Failed to authenticate token' });
    }

    res.json({ message: 'This is a protected endpoint', role: decoded.role });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
```

## 2. Stockage du JWT côté Client

Le client Angular stocke le JWT reçu après une connexion réussie.

### Service d'Authentification (Angular)

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { CookieService } from 'ngx-cookie-service';
import jwt_decode from 'jwt-decode';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private API_URL = 'http://localhost:3005/api';

  constructor(private http: HttpClient, private cookieService: CookieService) {}

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
        const decoded: any = jwt_decode(token);
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
```

## 3. Utilisation d'un Intercepteur HTTP

Un intercepteur HTTP ajoute automatiquement le JWT aux requêtes sortantes.

### Intercepteur (Angular)

```typescript
import { Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthService } from './auth.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

  constructor(private authService: AuthService) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token = this.authService.getToken();
    if (token) {
      const cloned = req.clone({ headers: req.headers.set('Authorization', `Bearer ${token}`) });
      console.log('JWT ajouté à la requête:', cloned);
      return next.handle(cloned);
    } else {
      return next.handle(req);
    }
  }
}
```

### Configuration de l'Intercepteur (Angular)

```typescript
import { ApplicationConfig } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withFetch, HTTP_INTERCEPTORS } from '@angular/common/http';
import { routes } from './app.routes';
import { provideClientHydration } from '@angular/platform-browser';
import { AuthInterceptor } from './services/auth-interceptor.service';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideClientHydration(),
    provideHttpClient(withFetch()),
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true }
  ],
};
```

## 4. Protection des Routes avec des Guards

Les guards vérifient si l'utilisateur est authentifié et possède le rôle requis avant de lui permettre d'accéder à certaines routes.

### Routes (Angular)

```typescript
import { Routes } from '@angular/router';
import { AdminComponent } from '../components/admin/admin.component';
import { UserComponent } from '../components/user/user.component';
import { LoginComponent } from '../components/login/login.component';
import { UnauthorizedComponent } from '../components/unauthorized/unauthorized.component';
import { AuthGuard } from '../guards/auth.guard';

export const routes: Routes = [
  { path: 'admin', component: AdminComponent, canActivate: [AuthGuard], data: { expectedRole: 'admin' } },
  { path: 'user', component: UserComponent, canActivate: [AuthGuard], data: { expectedRole: 'user' } },
  { path: 'login', component: LoginComponent },
  { path: 'unauthorized', component: UnauthorizedComponent },
  { path: '', redirectTo: '/login', pathMatch: 'full' }
];
```

### Guard (Angular)

```typescript
import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {

  constructor(private authService: AuthService, private router: Router) {}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
    const expectedRole = route.data['expectedRole'];
    const token = this.authService.getToken();
    
    if (token) {
      const decoded: any = jwt_decode(token);
      const userRole = decoded.role;
      
      if (userRole === expectedRole) {
        return true;
      } else {
        this.router.navigate(['unauthorized']);
        return false;
      }
    } else {
      this.router.navigate(['login']);
      return false;
    }
  }
}
```

## Conclusion

Ce guide couvre le processus de l'authentification JWT avec Angular et Express.js. Il inclut la génération et le stockage du JWT, l'utilisation d'un intercepteur pour ajouter automatiquement le JWT aux requêtes sortantes, et la protection des routes avec des guards. En suivant ces étapes, vous pouvez sécuriser votre application web en s'assurant que seuls les utilisateurs autorisés ont accès aux ressources protégées.
