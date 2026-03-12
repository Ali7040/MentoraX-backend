import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';
import { RefreshTokenStore } from './refresh-token.store';
import { RolesGuard } from './guards/roles.guard';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.ACCESS_SECRET || 'secretKey',
      signOptions: { expiresIn: '15m' }, // OWASP: Short-lived access tokens
    }),
  ],
  providers: [AuthService, JwtStrategy, RefreshTokenStore, RolesGuard],
  controllers: [AuthController],
  exports: [RolesGuard], // Export so other modules can use RolesGuard
})
export class AuthModule {}
