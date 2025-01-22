import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import { Repository } from 'typeorm';
import { SignUpDto } from 'src/auth/dto/signup.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  private sanitize<T>(obj: T, excludedFields: (keyof T)[]): Partial<T> {
    const sanitizedObj = { ...obj };
    excludedFields.forEach((field) => delete sanitizedObj[field]);
    return sanitizedObj;
  }

  async create(
    dto: SignUpDto & { passwordHash: string },
  ): Promise<Partial<User>> {
    const newUser = this.userRepository.create(dto);
    const savedUser = await this.userRepository.save(newUser);
    return this.sanitize(savedUser, ['passwordHash']);
  }

  findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOneBy({ email });
  }

  findById(id: string): Promise<User | null> {
    return this.userRepository.findOneBy({ id });
  }

  async profile(userId: string): Promise<Partial<User>> {
    const user = await this.findById(userId);
    return this.sanitize(user, ['passwordHash']);
  }

  async updateUserTOTP(userId: string, totp: string) {
    // Retrieve user
    const user = await this.findById(userId);

    if (!user) {
      throw new HttpException(
        'User with the provided ID does not exist',
        HttpStatus.NOT_FOUND,
      );
    }

    // update user totp
    user.totp = totp;

    return this.userRepository.save(user);
  }
}
