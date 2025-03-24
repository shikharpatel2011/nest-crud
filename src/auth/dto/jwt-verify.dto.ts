import { ApiProperty } from '@nestjs/swagger';
export class JwtVerifyDto {
    @ApiProperty()
    token: string;
}
