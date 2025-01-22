import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { LogInDto } from './dto/login.dto';
import { Response } from 'express';
import { TwoFactorAuthDto } from './dto/two-factor-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(@Body() dto: SignUpDto, @Res() res: Response) {
    const result = await this.authService.signup(dto);

    // Generate HTML response
    const html = `
      <html>
        <body style="text-aign: center; font-family: Arial. sans-serif;">
          <h3>Scan the QR Code to Set Up 2FA</h2>
          <img src="${result.image}" alt="QR Code" style="margin-top: 20px" />
        </body>
      </html>
    `;

    res.setHeader('Content-Type', 'text/html');
    res.status(HttpStatus.CREATED).send(html);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  signin(@Body() dto: LogInDto) {
    return this.authService.login(dto);
  }

  @Post('/two-factor-auth')
  @HttpCode(HttpStatus.OK)
  twoFactorAuth(@Body() dto: TwoFactorAuthDto) {
    return this.authService.twoFactorAuth(dto.userId, dto.token);
  }
}
