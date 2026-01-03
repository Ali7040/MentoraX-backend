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

  async login(email: string, password: string) {
    try {
      const user = await this.validateUser(email, password);
      if (!user) {
        return null;
      }
      const payload = { id: user.id, email: user.email };
      const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
      return { accessToken };
    } catch {
      return null;
    }
  }
}
