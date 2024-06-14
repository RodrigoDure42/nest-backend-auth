import {
    BadRequestException,
    Injectable,
    InternalServerErrorException,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import * as bcryptjs from 'bcryptjs';
import { Model } from 'mongoose';
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateUserDto } from './dto';
import { User } from './entities/user.entity';
import { IJwtPayload, ILoginResponse } from './interfaces';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private jwtService: JwtService,
    ) {}

    async create(createAuthDto: CreateUserDto): Promise<User> {
        try {
            const { password, ...userData } = createAuthDto;
            const newUser = new this.userModel({
                ...userData,
                password: bcryptjs.hashSync(password, 10),
            });
            await newUser.save();
            const { password: _, ...user } = newUser.toJSON();
            return user;
        } catch (error) {
            if (error.code === 11000) {
                throw new BadRequestException('User already exists');
            }
            throw new InternalServerErrorException(
                'Something terrible happened!!',
            );
        }
    }

    async findAll(): Promise<User[]> {
        return await this.userModel.find();
    }

    async findOne(id: string): Promise<User> {
        const user = await this.userModel.findById(id);
        const { password, ...rest } = user.toJSON();
        return rest;
    }

    async update(id: string, updateAuthDto: UpdateUserDto): Promise<User> {
        return await this.userModel.findByIdAndUpdate(id, updateAuthDto, {
            new: true,
        });
    }

    async remove(id: number): Promise<void> {
        await this.userModel.findByIdAndDelete(id);
    }

    async login(loginDto: LoginDto): Promise<ILoginResponse> {
        const { password, email } = loginDto;
        const user = await this.userModel.findOne({ email });
        if (!user) {
            throw new BadRequestException('User not found');
        }
        if (!bcryptjs.compareSync(password, user.password)) {
            throw new UnauthorizedException('Invalid credentials');
        }
        const { password: _, ...rest } = user.toJSON();
        return {
            user: rest,
            token: this.getJwtToken({ id: user.id }),
        };
    }

    async register(registerUserDto: RegisterUserDto): Promise<ILoginResponse> {
        const user = await this.create(registerUserDto);
        return {
            user: user,
            token: this.getJwtToken({ id: user._id }),
        };
    }

    getJwtToken(payload: IJwtPayload): string {
        return this.jwtService.sign(payload);
    }
}
