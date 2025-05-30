import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: '*',
    allowedHeaders: ['Content-Type', 'Authorization'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  });

  const config = new DocumentBuilder()
    .setTitle('Auth API')
    .setDescription(
      'User Registration with CRUD Operations made using Node.js with NestJS, MongoDB with Prisma, JWT, and SwaggerUI. Also features sending OTP to email for verification using Nodemailer.'
    )
    .setVersion('1.0')
    .addTag('auth')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        in: 'header',
      },
      'access-token'
    )
    .addServer('http://localhost:3000', 'Local Development')
    .addServer('https://nest-crud-moi0.onrender.com', 'Production - Render')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  await app.listen(process.env.PORT || 3000);
}
bootstrap();
