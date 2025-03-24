import {
  Injectable,
  NotFoundException,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { PrismaService } from 'prisma/prisma.service';
import { User } from '@prisma/client';
import { generateOTP } from '../utils/otp.util';
import { sendOTPEmail } from '../utils/email.util';
import { HttpException, HttpStatus } from '@nestjs/common';
@Injectable()
export class AuthService {
  private readonly jwtSecret = process.env.JWT_SECRET;

  constructor(private readonly prisma: PrismaService) {}


  async sendOtp(email: string, password: string,firstName: string,lastName: string,action: 'create' | 'delete'): Promise<void> {
    const otp = generateOTP();
    const generatedAt = new Date(); 
    await this.prisma.user.upsert({
      where: { email },
      update: { otp, password , firstName, lastName,action,generatedAt},
      create: { email, otp, password , firstName, lastName,action,generatedAt},
    });
    await sendOTPEmail(email, otp);
  }
  
  async verifyOtp(otp: string): Promise<any> {
    const user = await this.prisma.user.findFirst({ where: { otp } });
  
    if (!user || user.otp !== otp) {
      throw new BadRequestException('Invalid OTP');
    }
    const currentTime = new Date();
    const otpAge = (currentTime.getTime() - new Date(user.generatedAt).getTime()) / 1000; 
    
    if (otpAge > 60) {
      throw new HttpException('OTP expired to Resend it Proceed again', HttpStatus.BAD_REQUEST);
    }
    if (user.action === 'create') {
      const createdUser = await this.prisma.user.update({
        where: { email: user.email },
        data: { otp: null },  
      });
      return {
        message: 'User created successfully!',
        user: createdUser,
      };
    } else if (user.action === 'delete') {
      await this.prisma.user.delete({
        where: { email: user.email },
        
      });
      return {
        message: `User with email ${user.email} deleted successfully.`,
        user: user,
      };
    } else {
      throw new BadRequestException('Invalid action or user state.');
    }
  }
  
  

  async login(email: string, password: string): Promise<{ token: string; user: User }> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.password !== password) {
      throw new UnauthorizedException('Invalid password');
    }

    const token = jwt.sign({ userId: user.id }, this.jwtSecret, { expiresIn: '1h' });

    return { token, user };
  }

  async resetPassword(email: string, newPassword: string): Promise<string> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    await this.prisma.user.update({
      where: { email },
      data: { password: newPassword },
    });

    return `Password for ${email} has been reset successfully.`;
  }

  async verifyToken(token: string): Promise<any> {
    try {
      const decoded = jwt.verify(token, this.jwtSecret);
      return decoded;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }

  async getUserByEmail(email: string): Promise<{ email: string; firstName: string; lastName: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        email: true,
        firstName: true,
        lastName: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }
  
  async getUsers(): Promise<User[]> {
    return this.prisma.user.findMany();
  }
}
