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

