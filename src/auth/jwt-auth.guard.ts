import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly jwtSecret = process.env.JWT_SECRET; 

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;

    if (!authHeader) {
      console.log('Authorization header missing');
      return false;
    }
    const token = authHeader.split(' ')[1];

    try {

      const decoded = jwt.verify(token, this.jwtSecret);
      request.user = decoded;
      console.log('Token verified successfully:', decoded);
      return true;
    } catch (error) {
      console.log('Token verification failed:', error.message);
      return false;
    }
  }
}
