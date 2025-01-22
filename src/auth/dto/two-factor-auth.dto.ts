import { IsNotEmpty, IsString } from 'class-validator';

export class TwoFactorAuthDto {
  @IsString()
  @IsNotEmpty()
  userId: string;

  @IsString()
  @IsNotEmpty()
  token: string;
}
