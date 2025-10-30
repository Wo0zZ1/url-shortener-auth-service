import { Module } from '@nestjs/common'

import { ClientsModule } from '@nestjs/microservices'
import { HttpModule } from '@nestjs/axios'
import { JwtModule } from '@nestjs/jwt'

import { AuthService } from './auth.service'
import { AuthEventHandler } from './auth.event-handler'
import { PrismaService } from '../prisma/prisma.service'
import { UsersHttpClient } from '../users/user.http-client'

import { AuthController } from './auth.controller'
import { getEventEmitterConfig } from '@wo0zz1/url-shortener-shared'

@Module({
	imports: [
		ClientsModule.register([getEventEmitterConfig(process.env.RABBITMQ_URL!)]),
		HttpModule,
		JwtModule.register({}),
	],
	controllers: [AuthController, AuthEventHandler],
	providers: [AuthService, PrismaService, UsersHttpClient],
	exports: [AuthService],
})
export class AuthModule {}
