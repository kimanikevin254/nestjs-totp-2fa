import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { SignUpDto } from './dto/signup.dto';
import { LogInDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as OTPAuth from 'otpauth';
import * as QRCode from 'qrcode';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  private async hashPassword(password: string): Promise<string> {
    const saltOrRounds = 10;
    return await bcrypt.hash(password, saltOrRounds);
  }

  private async generateTokens(userId: string) {
    const accessTokenTtlMins =
      this.configService.getOrThrow<number>('config.jwt.ttl');

    const accessToken = await this.jwtService.signAsync(
      { sub: userId },
      { expiresIn: accessTokenTtlMins * 60 }, //secs
    );

    return { access: accessToken };
  }

  private generateTOTP(email: string): OTPAuth.TOTP {
    return new OTPAuth.TOTP({
      issuer: 'NestJS App',
      label: email,
      algorithm: 'SHA256',
      digits: 6,
      period: 30,
      secret: new OTPAuth.Secret(),
    });
  }

  private async generateQRCode(totp: OTPAuth.TOTP): Promise<string> {
    const totpURI = OTPAuth.URI.stringify(totp);
    return QRCode.toDataURL(totpURI);
  }

  private serializeTOTP(totp: OTPAuth.TOTP) {
    return JSON.stringify({
      issuer: totp.issuer,
      label: totp.label,
      issuerInLabel: totp.issuerInLabel,
      secret: totp.secret.hex,
      algorithm: totp.algorithm,
      digits: totp.digits,
      period: totp.period,
    });
  }

  private deserializeTOTP(totpString: string): OTPAuth.TOTP {
    const parsed = JSON.parse(totpString);

    return new OTPAuth.TOTP({
      issuer: parsed.issuer,
      label: parsed.label,
      issuerInLabel: parsed.issuerInLabel,
      secret: OTPAuth.Secret.fromHex(parsed.secret),
      algorithm: parsed.algorithm,
      digits: parsed.digits,
      period: parsed.period,
    });
  }

  private validateTOTP(token: string, totp: OTPAuth.TOTP) {
    return totp.validate({ token, window: 1 });
  }

  async signup(dto: SignUpDto) {
    // Check is user exists
    const user = await this.userService.findByEmail(dto.email);

    if (user) {
      throw new HttpException(
        'Email address is already registered.',
        HttpStatus.BAD_REQUEST,
      );
    }

    // Hash password
    const passwordHash = await this.hashPassword(dto.password);

    const newUser = await this.userService.create({ ...dto, passwordHash });

    // Generate TOTP object
    const totp = this.generateTOTP(newUser.email);

    // Serialize totp
    const serializedTOTP = this.serializeTOTP(totp);

    // Save user TOTP
    await this.userService.updateUserTOTP(newUser.id, serializedTOTP);

    // Generate QR code for user to scan
    const qrCode = await this.generateQRCode(totp);

    return { image: qrCode };
  }

  async login(dto: LogInDto) {
    const user = await this.userService.findByEmail(dto.email);

    if (!user) {
      throw new HttpException('Incorrect credentials', HttpStatus.UNAUTHORIZED);
    }

    // Check if password matches
    const passwordMatches = await bcrypt.compare(
      dto.password,
      user.passwordHash,
    );

    if (!passwordMatches) {
      throw new HttpException('Incorrect credentials', HttpStatus.UNAUTHORIZED);
    }

    return {
      message: 'Provide the OTP from your Authenticator app',
      userId: user.id,
    };
  }

  async twoFactorAuth(userId: string, token: string) {
    // Retrieve user
    const user = await this.userService.findById(userId);

    // Deserialize saved totp
    const deserializedTOTP = this.deserializeTOTP(user.totp);

    // Validate token
    if (this.validateTOTP(token, deserializedTOTP) === null) {
      throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
    }

    const tokens = await this.generateTokens(user.id);

    return {
      tokens,
      userId: user.id,
    };
  }
}
