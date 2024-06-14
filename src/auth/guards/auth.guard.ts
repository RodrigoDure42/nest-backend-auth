import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        private jwtService: JwtService,
        private authService: AuthService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);
        if (!token) {
            throw new UnauthorizedException();
        }
        try {
            const payload = await this.jwtService.verifyAsync(token, {
                secret: process.env.JWT_SEED,
            });
            const user = await this.authService.findOne(payload.id);
            if (!user) {
                throw new UnauthorizedException('User not exists');
            }
            if (!user.active) {
                throw new UnauthorizedException('User not active');
            }
            request['user'] = user;
        } catch (error) {
            console.log(error);
            throw new UnauthorizedException();
        }
        return Promise.resolve(true);
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] =
            request.headers['authorization']?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}
