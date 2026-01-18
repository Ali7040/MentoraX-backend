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
    res.cookie('refreshToken', token.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
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
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
    return res.status(200).json(tokens);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req: Request, @Res() res: Response) {
    return res.status(200).json(req.user);
  }
}