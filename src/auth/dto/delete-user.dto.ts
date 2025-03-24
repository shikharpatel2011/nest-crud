
import { IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class DeleteUserDto {
  @ApiProperty({ description: 'Email of the user to delete' })
  @IsEmail()
  email: string;
}
