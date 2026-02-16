import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

interface RefreshToken {
  userId: number;
  tokenHash: string;
  isRevoked: boolean;
  expiresAt: Date;
  createdAt: Date;
  family?: string; // Token family for rotation tracking
}

@Injectable()
export class RefreshTokenStore {
  private tokens: RefreshToken[] = [];

  async save(userId: number, token: string, family?: string): Promise<void> {
    const hash = await bcrypt.hash(token, 10);
    this.tokens.push({
      userId,
      tokenHash: hash, // ✅ Fixed: Store hash instead of plaintext
      isRevoked: false,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      createdAt: new Date(),
      family,
    });
  }

  async findValid(userId: number, token: string): Promise<RefreshToken | null> {
    // Clean up expired tokens first
    this.cleanupExpired();

    for (const t of this.tokens) {
      if (t.userId === userId && !t.isRevoked && t.expiresAt > new Date()) {
        const match = await bcrypt.compare(token, t.tokenHash);
        if (match) return t;
      }
    }
    return null;
  }

  async isTokenRevoked(userId: number, token: string): Promise<boolean> {
    const storedToken = await this.findToken(userId, token);
    return storedToken ? storedToken.isRevoked : true;
  }

  async findToken(userId: number, token: string): Promise<RefreshToken | null> {
    for (const t of this.tokens) {
      if (t.userId === userId) {
        const match = await bcrypt.compare(token, t.tokenHash);
        if (match) return t;
      }
    }
    return null;
  }

  revoke(token: RefreshToken): void {
    token.isRevoked = true;
  }

  async revokeToken(userId: number, token: string): Promise<boolean> {
    const storedToken = await this.findToken(userId, token);
    if (storedToken) {
      storedToken.isRevoked = true;
      return true;
    }
    return false;
  }

  revokeAll(userId: number): void {
    this.tokens.forEach((t) => {
      if (t.userId === userId) t.isRevoked = true;
    });
  }

  // Revoke all tokens in a family (for compromised token detection)
  revokeFamily(family: string): void {
    this.tokens.forEach((t) => {
      if (t.family === family) t.isRevoked = true;
    });
  }

  // Clean up expired and old revoked tokens
  private cleanupExpired(): void {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    this.tokens = this.tokens.filter(
      (t) =>
        t.expiresAt > now ||
        (t.isRevoked && t.createdAt > thirtyDaysAgo), // Keep revoked tokens for 30 days for audit
    );
  }
}