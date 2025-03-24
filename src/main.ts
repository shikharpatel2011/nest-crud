import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({allowedHeaders: 'Authorization'});
  const config = new DocumentBuilder()
    .setTitle('Auth API')
    .setDescription('User Registration with CRUD Operations made using Nodejs with NESTJS, MongoDB with Prisma, JWT and SwaggerUI. Also Features sending OTP to email for verification using Nodemailer.') 
    .setVersion('1.0')
    .addTag('auth')
    .addBearerAuth( 
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
      },
      'access-token',
    )
    .addServer('http://localhost:3000', 'HTTP Server') 
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document); 

  await app.listen(3000);
}
bootstrap();
