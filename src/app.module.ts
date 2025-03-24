import { Module } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';  
import { PrismaModule } from '../prisma/prisma.module'; 
import { AppController } from './app.controller';
import { PrismaService } from '../prisma/prisma.service';
@Module({
  imports: [AuthModule, PrismaModule], 
  controllers: [AppController], 
  providers: [AppService,PrismaService],
})
export class AppModule {}
