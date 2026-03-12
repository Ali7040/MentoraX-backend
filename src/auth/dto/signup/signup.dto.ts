import { Role } from '../../roles/role.enum';

export class SignupDto {
  email: string;
  password: string;

  /**
   * Optional role for signup.
   * In production, this should ONLY be settable by admins via a separate endpoint.
   * For development/testing, we allow it here.
   * Default: Role.STUDENT (Principle of Least Privilege — OWASP)
   */
  role?: Role;
}
