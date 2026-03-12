/**
 * Role Enum — Defines all user roles in the MentoraX platform.
 *
 * OWASP Best Practice:
 * - Use an enum (not raw strings) to prevent typos and unauthorized role injection.
 * - Roles follow the Principle of Least Privilege: users get the minimum role needed.
 *
 * Hierarchy (ascending privilege):
 *   STUDENT < INSTRUCTOR < ADMIN
 *
 * Industry reference:
 *   Google Workspace, GitHub, AWS IAM — all use a fixed set of predefined roles.
 */
export enum Role {
  /** Default role for every new user. Can view courses and complete lessons. */
  STUDENT = 'student',

  /** Can do everything a student can, plus create and manage their own courses. */
  INSTRUCTOR = 'instructor',

  /** Full platform access — manage users, courses, settings. */
  ADMIN = 'admin',
}

/**
 * Why use an enum?
 * ─────────────────────────────────
 * 1. Type safety — TypeScript catches invalid roles at compile time.
 * 2. Single source of truth — one file defines all roles.
 * 3. Refactor-friendly — rename in one place, the compiler shows every usage.
 * 4. Prevents injection — guards compare against enum values, not arbitrary strings.
 */
