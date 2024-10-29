import { Controller, Post, Body, Headers, Get } from '@nestjs/common';
import { UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  async signup(@Body() body: { email: string; password: string }) {
    return this.authService.signup(body.email, body.password);
  }

  @Post('login')
  async login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }

  @Get('verify')
  async verifyToken(@Headers('authorization') auth: string) {
    if (!auth) throw new UnauthorizedException();
    const token = auth.split(' ')[1];
    return this.authService.verifyToken(token);
  }

  @Post('update-scrapes')
  async updateScrapes(@Headers('authorization') auth: string) {
    if (!auth) throw new UnauthorizedException();
    const token = auth.split(' ')[1];
    return this.authService.updateScrapes(token);
  }
}
