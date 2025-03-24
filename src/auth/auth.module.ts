import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller'; 
import { PrismaModule } from 'prisma/prisma.module';
import { PrismaService } from 'prisma/prisma.service';
import { JwtAuthGuard } from './jwt-auth.guard';

@Module({
  imports: [PrismaModule], 
  controllers: [AuthController],  
  providers: [AuthService,PrismaService,JwtAuthGuard], 
})
export class AuthModule {}
