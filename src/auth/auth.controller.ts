import {
  Controller,
  Post,
  Body,
  Res,
  Req,
  UseGuards,
  Get,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup/signup.dto';
import { LoginDto } from './dto/login/login.dto';
import { Response, Request } from 'express';
import { JwtAuthGuard } from './jwt-auth.guard';

interface RequestWithCookies extends Request {
  cookies: { [key: string]: string };
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signUp(@Body() signupDto: SignupDto, @Res() res: Response) {
    const user = await this.authService.signUp(
      signupDto.email,
      signupDto.password,
    );
    return res.status(201).json(user);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto, @Res() res: Response) {
    const user = await this.authService.validateUser(
      loginDto.email,
      loginDto.password,
    );
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token: { accessToken: string; refreshToken: string } | null =
      await this.authService.login(user);
    if (!token) {
      return res.status(500).json({ message: 'Token generation failed' });
    }
    // OWASP Best Practice: HttpOnly, Secure, SameSite cookie
    res.cookie('refreshToken', token.refreshToken, {
      httpOnly: true, // Prevents XSS attacks - JS cannot access
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict', // CSRF protection
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });
    return res
      .status(200)
      .json({ user, token: { accessToken: token.accessToken } });
  }

  @Post('refresh-token')
  async refreshToken(@Req() req: RequestWithCookies, @Res() res: Response) {
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: 'No refresh token provided' });
    }
    const tokens: { accessToken: string; refreshToken: string } | null =
      await this.authService.refreshTokens(refreshToken);
    if (!tokens) {
      // Clear invalid cookie
      res.clearCookie('refreshToken');
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    // OWASP Best Practice: Rotate refresh token (single-use tokens)
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true, // Prevents XSS attacks - JS cannot access
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict', // CSRF protection
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });

    // ✅ Only return access token in JSON
    return res.status(200).json({ accessToken: tokens.accessToken });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Req() req: Request, @Res() res: Response) {
    const refreshToken = (req as RequestWithCookies).cookies?.refreshToken;
    const userId = (req.user as any)?.id;

    if (userId && refreshToken) {
      await this.authService.logout(userId, refreshToken);
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken', { path: '/' });
    return res.status(200).json({ message: 'Logged out successfully' });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  async logoutAll(@Req() req: Request, @Res() res: Response) {
    const userId = (req.user as any)?.id;

    if (userId) {
      await this.authService.logoutAll(userId);
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken', { path: '/' });
    return res
      .status(200)
      .json({ message: 'Logged out from all devices successfully' });
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req: Request, @Res() res: Response) {
    return res.status(200).json(req.user);
  }
}