import { Controller, Post, Body, Get, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto'; 
import { LoginDto } from './dto/login.dto'; 
import { ResetPasswordDto } from './dto/reset-password.dto'; 
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { UserDto } from './dto/user.dto';  
import { ConfirmOtpDto } from './dto/confirm-otp.dto';
import { FindUserByEmailDto } from './dto/find-user-by-email.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { JwtVerifyDto } from './dto/jwt-verify.dto'; 
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @ApiOperation({ summary: 'Create a new user' })
  @ApiResponse({ status: 201, description: 'OTP sent to email' })
  @ApiResponse({ status: 400, description: 'Bad Request.' })
  async signup(@Body() signupDto: CreateUserDto) {
    const { email, password, firstName, lastName } = signupDto;
    await this.authService.sendOtp(email, password, firstName, lastName, 'create');
    return { message: 'OTP sent to email' };
  }

  @Post('confirm-otp')
  @ApiOperation({ summary: 'Verify OTP to either create or delete user' })
  @ApiResponse({ status: 201, description: 'Action successful' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  async confirmOtp(@Body() confirmOtpDto: ConfirmOtpDto) {
    const { otp } = confirmOtpDto;
    const message = await this.authService.verifyOtp(otp);
    return { message };
  }

  @Post('login')
  @ApiOperation({ summary: 'Log in a user' })
  @ApiResponse({ status: 200, description: 'Login successful.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  async login(@Body() loginDto: LoginDto) {
    const { email, password } = loginDto;
    const { token, user } = await this.authService.login(email, password);
    return { message: 'Login successful', token, user };
  }

  @Post('forgot password? reset it here')
  @ApiOperation({ summary: 'Reset user password' })
  @ApiResponse({ status: 200, description: 'Password reset successful.' })
  @ApiResponse({ status: 400, description: 'Bad Request.' })
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    const { email, newPassword } = resetPasswordDto;
    const response = await this.authService.resetPassword(email, newPassword);
    return response;
  }

  @UseGuards(JwtAuthGuard)
  @Post('delete')
  @ApiOperation({ summary: 'Send OTP to delete user (Requires JWT Authorization)' })
  @ApiResponse({ status: 200, description: 'OTP sent to delete user.' })
  @ApiResponse({ status: 400, description: 'Bad Request.' })
  @ApiBearerAuth('access-token')
  async deleteUser(@Body() deleteUserDto: DeleteUserDto) {
    const { email } = deleteUserDto;
    await this.authService.sendOtp(email, '', '', '', 'delete');
    return { message: 'OTP sent to delete user' };
  }

  @Post('get-user-by-email')
  @ApiOperation({ summary: 'Get user by email' })
  @ApiResponse({ status: 200, description: 'User Found.' })
  @ApiResponse({ status: 401, description: 'User not Found.' })
  async getUserByEmail(@Body() findUserByEmailDto: FindUserByEmailDto) {
    const { email } = findUserByEmailDto;
    const user = await this.authService.getUserByEmail(email);
    return user;
  }

  @Post('verify-token')
  @ApiOperation({ summary: 'Verify JWT Token' })
  @ApiResponse({ status: 200, description: 'Token Verified.' })
  @ApiResponse({ status: 400, description: 'Invalid Token.' })
  async verifyToken(@Body() jwtVerifyDto: JwtVerifyDto) {
    const { token } = jwtVerifyDto;
    const decoded = await this.authService.verifyToken(token); 
    return { decoded }; 
  }

  @UseGuards(JwtAuthGuard)
  @Get('users')
  @ApiOperation({ summary: 'Get all users (Requires JWT Authorization)' })
  @ApiResponse({ status: 200, description: 'List of all users', type: [UserDto] })
  @ApiBearerAuth('access-token')
  async getUsers() {
    return this.authService.getUsers();
  }
}
