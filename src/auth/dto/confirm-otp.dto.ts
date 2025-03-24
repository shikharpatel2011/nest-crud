import { IsEmail, IsString ,MinLength} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ConfirmOtpDto {
  @ApiProperty()
  @IsString()
  otp: string;

}
