import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { SignUpDto } from './dto/signup.dto';
import { LogInDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

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

    // Generate tokens
    const tokens = await this.generateTokens(newUser.id);

    return { tokens };
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

    // Generate tokens
    const tokens = await this.generateTokens(user.id);

    return {
      tokens,
      userId: user.id,
    };
  }
}
