import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';

import * as bcrypt from 'bcryptjs';

import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name )
    private userModel: Model<User>,
    private jwtService: JwtService,
  ){}
  
  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      const { password, ...userData } = createUserDto // Destructura el objeto del request
	
	    const newUser = new this.userModel({   // Instanciamos nuestro modelo para crear un nuevo usuario
		  password: bcrypt.hashSync(password, 10), // A la propiedad password la encriptamos
		  ...userData // Agregamos las otras propiedades que construyen nuestro modelo
	    });
	
      await newUser.save() //Se guarda el registro
      
      const { password:_, ...user } = newUser.toJSON();  // Desestructuramos el newUser para serparar la contraseña
      return user; // Devolvemos un objeto sin la propiedad password


    } catch (error) {
      if( error.code == 11000 ) {
        throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException('Something terrible happends')
    }

  }

  async register(registerUserDto: RegisterUserDto) {

    const user = await this.create( registerUserDto );

    return {
      user: user,
      token: this.getJwtToken({ id: user._id }),
    }
  } 

  async login(loginDto:LoginDto): Promise<LoginResponse> {

    const {email, password} = loginDto;

    const user = await this.userModel.findOne({email});

    if( !user ) {
      throw new UnauthorizedException('Not valid credentials - email');
    }

    if( !bcrypt.compareSync(password, user.password) ) {
      throw new UnauthorizedException('Not valid credentials - password');
    }

    const {password:_, ...rest} = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id })
    }
  }


  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id: string ){
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken( payload: JwtPayload ) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
