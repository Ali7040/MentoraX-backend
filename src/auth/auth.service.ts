import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { RefreshTokenStore } from './refresh-token.store';
import { randomBytes } from 'crypto';

interface User {
  id: number;
  email: string;
  password: string;
}

@Injectable()
export class AuthService {
  private users: User[] = [];
  constructor(
    private readonly jwtService: JwtService,
    private readonly refreshTokenStore: RefreshTokenStore,
  ) {}
  async signUp(email: string, password: string) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user: User = { id: Date.now(), email, password: hashedPassword };
    this.users.push(user);
    return { id: user.id, email: user.email };
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = this.users.find((u) => u.email === email);
    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }
    return null;
  }

  async login(
    user: User,
  ): Promise<{ accessToken: string; refreshToken: string } | null> {
    const payload = { id: user.id, email: user.email };
    const family = randomBytes(16).toString('hex'); // Token family for rotation tracking

    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(
      { ...payload, family },
      { expiresIn: '7d' },
    );

    // Save refresh token to store
    await this.refreshTokenStore.save(user.id, refreshToken, family);

    return { accessToken, refreshToken };
  }

  async refreshTokens(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string } | null> {
    try {
      // Verify JWT signature and expiration
      const payload = this.jwtService.verify(refreshToken);
      const userId = payload.id;
      const family = payload.family;

      // Check if token exists and is valid in store
      const storedToken =
        await this.refreshTokenStore.findValid(userId, refreshToken);

      if (!storedToken) {
        // Token not found or already revoked
        // If it was revoked but JWT is still valid, might be a replay attack
        const isRevoked =
          await this.refreshTokenStore.isTokenRevoked(userId, refreshToken);
        if (isRevoked && family) {
          // Possible token theft - revoke entire family
          this.refreshTokenStore.revokeFamily(family);
        }
        return null;
      }

      // ✅ Revoke old refresh token (rotation)
      this.refreshTokenStore.revoke(storedToken);

      // Generate new tokens with same family
      const newPayload = { id: payload.id, email: payload.email };
      const newAccessToken = this.jwtService.sign(newPayload, {
        expiresIn: '15m',
      });
      const newRefreshToken = this.jwtService.sign(
        { ...newPayload, family },
        { expiresIn: '7d' },
      );

      // Save new refresh token to store
      await this.refreshTokenStore.save(userId, newRefreshToken, family);

      return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    } catch {
      return null;
    }
  }

  async logout(userId: number, refreshToken: string): Promise<boolean> {
    return await this.refreshTokenStore.revokeToken(userId, refreshToken);
  }

  async logoutAll(userId: number): Promise<void> {
    this.refreshTokenStore.revokeAll(userId);
  }
}
