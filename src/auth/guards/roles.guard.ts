import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '../roles/role.enum';
import { ROLES_KEY } from '../decorators/roles.decorator';

/**
 * RolesGuard — Enforces Role-Based Access Control (RBAC) at the route level.
 *
 * Execution flow:
 *   1. Reads the roles attached via @Roles() decorator (metadata).
 *   2. If no roles are set on the handler, the route is public to all
 *      authenticated users (guard returns true).
 *   3. Extracts the user object from the request (set by JwtAuthGuard + JwtStrategy).
 *   4. Checks if the user's role is included in the allowed roles.
 *   5. If not, throws ForbiddenException (HTTP 403).
 *
 * OWASP Best Practices applied:
 *   - Deny by default: if the user has no role, access is denied.
 *   - Centralized authorization logic: one guard, every route.
 *   - Fail securely: unknown/missing roles result in denial, not access.
 *
 * Used by:
 *   Google Cloud IAM, AWS IAM, GitHub Org Roles, Stripe Dashboard Roles.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // 1. Get required roles from @Roles() decorator metadata
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // 2. No @Roles() decorator → route is open to any authenticated user
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    // 3. Extract user from request (populated by JwtAuthGuard)
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    // 4. Deny if no user or no role
    if (!user || !user.role) {
      throw new ForbiddenException(
        'Access denied: insufficient permissions. No role assigned.',
      );
    }

    // 5. Check if the user's role matches any of the required roles
    const hasRole = requiredRoles.includes(user.role);

    if (!hasRole) {
      throw new ForbiddenException(
        `Access denied: requires one of [${requiredRoles.join(', ')}], but you have [${user.role}].`,
      );
    }

    return true;
  }
}
