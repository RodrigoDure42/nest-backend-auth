import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class RegisterUserDto {
    @IsEmail()
    email: string;

    @IsNotEmpty()
    name: string;

    @MinLength(6)
    password: string;
}
