import { Module } from '@nestjs/common'

import { ClientsModule } from '@nestjs/microservices'
import { HttpModule } from '@nestjs/axios'
import { JwtModule, JwtService } from '@nestjs/jwt'
import { getUserServiceConfig } from '@wo0zz1/url-shortener-shared'

import { AuthService } from './auth.service'
import { PrismaService } from '../prisma/prisma.service'
import { UsersHttpClient } from '../users/user.http-client'

import { AuthController } from './auth.controller'

@Module({
	imports: [
		ClientsModule.register([getUserServiceConfig(process.env.RABBITMQ_URL!)]),
		HttpModule,
		JwtModule.register({}),
	],
	providers: [AuthService, PrismaService, JwtService, UsersHttpClient],
	controllers: [AuthController],
	exports: [AuthService],
})
export class AuthModule {}
