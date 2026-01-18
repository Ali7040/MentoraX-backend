import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

interface User {
  id: number;
  email: string;
  password: string;
}

@Injectable()
export class AuthService {
  private users: User[] = [];
  constructor(private readonly jwtService: JwtService) {}
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

  login(user: User): { accessToken: string; refreshToken: string } | null {
    const payload = { id: user.id, email: user.email };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });
    return { accessToken, refreshToken };
  }

  async refreshTokens(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string } | null> {
    try {
      const user: User = this.jwtService.verify(refreshToken);
      const payload = { id: user.id, email: user.email };
      const newAccessToken: string = await this.jwtService.signAsync(payload, {
        expiresIn: '15m',
      });
      const newRefreshToken: string = await this.jwtService.signAsync(payload, {
        expiresIn: '7d',
      });
      return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    } catch {
      return null;
    }
  }
}
