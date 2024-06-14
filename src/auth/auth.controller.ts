import {
    Controller,
    Get,
    Post,
    Body,
    Patch,
    Param,
    Delete,
    UseGuards,
    Request,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, UpdateUserDto, LoginDto, RegisterUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post()
    @UseGuards(AuthGuard)
    create(@Body() createAuthDto: CreateUserDto) {
        return this.authService.create(createAuthDto);
    }

    @Get()
    @UseGuards(AuthGuard)
    findAll() {
        return this.authService.findAll();
    }

    @Post('login')
    login(@Body() loginDto: LoginDto) {
        return this.authService.login(loginDto);
    }

    @Post('register')
    register(@Body() registerUserDto: RegisterUserDto) {
        return this.authService.register(registerUserDto);
    }

    @Get('check-token')
    @UseGuards(AuthGuard)
    checkToken(@Request() req: Request) {
        const user = req['user'];
        return {
            user: user,
            token: this.authService.getJwtToken({ id: user._id }),
        };
    }

    @Get(':id')
    @UseGuards(AuthGuard)
    findOne(@Param('id') id: string) {
        return this.authService.findOne(id);
    }

    @Patch(':id')
    @UseGuards(AuthGuard)
    update(@Param('id') id: string, @Body() updateAuthDto: UpdateUserDto) {
        return this.authService.update(id, updateAuthDto);
    }

    @Delete(':id')
    @UseGuards(AuthGuard)
    remove(@Param('id') id: string) {
        return this.authService.remove(+id);
    }
}
