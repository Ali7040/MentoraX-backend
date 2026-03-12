import { SetMetadata } from '@nestjs/common';
import { Role } from '../roles/role.enum';

/**
 * Metadata key used by the RolesGuard to read the required roles.
 * Exported so the guard can use the same constant — avoids magic strings.
 */
export const ROLES_KEY = 'roles';

/**
 * @Roles() — Custom decorator to mark endpoints with required roles.
 *
 * Usage:
 *   @Roles(Role.ADMIN)            — only admins
 *   @Roles(Role.ADMIN, Role.INSTRUCTOR) — admins OR instructors
 *
 * How it works:
 *   SetMetadata attaches the role list to the route handler's metadata.
 *   The RolesGuard reads this metadata via Reflector and decides access.
 *
 * OWASP Best Practice:
 *   Declarative access control — roles are defined at the handler level,
 *   making security requirements visible and auditable in code reviews.
 *
 * Industry usage:
 *   NestJS official docs, Spring Security @PreAuthorize, ASP.NET [Authorize(Roles)]
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
