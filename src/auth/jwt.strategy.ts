import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';


@Injectable()export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        ignoreExpiration: false,
        secretOrKey: process.env.ACCESS_SECRET || 'secretKey',
    });
  }
    /**
     * The return value is attached to request.user.
     * Including `role` here makes it available to RolesGuard.
     */
    async validate(payload: any) {
        return { id: payload.id, email: payload.email, role: payload.role };
    }
}