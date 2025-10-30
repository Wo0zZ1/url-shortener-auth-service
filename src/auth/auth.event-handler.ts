import { Controller } from '@nestjs/common'
import { Channel, Message } from 'amqplib'
import { Ctx, EventPattern, Payload, RmqContext } from '@nestjs/microservices'

import { EEventPattern, type UserDeletedEvent } from '@wo0zz1/url-shortener-shared'

import { PrismaService } from 'src/prisma/prisma.service'

@Controller()
export class AuthEventHandler {
	constructor(private readonly prismaService: PrismaService) {}

	ack(context: RmqContext) {
		const channel = context.getChannelRef() as Channel
		const originalMsg = context.getMessage() as Message
		channel.ack(originalMsg)
	}

	nack(context: RmqContext) {
		const channel = context.getChannelRef() as Channel
		const originalMsg = context.getMessage() as Message
		channel.nack(originalMsg, false, true)
	}

	@EventPattern(EEventPattern.USER_DELETED)
	async handleUserDeleted(@Payload() data: UserDeletedEvent, @Ctx() context: RmqContext) {
		console.log('Auth Service: Received user deleted event:', data)

		try {
			await this.prismaService.jwtRefreshToken.deleteMany({
				where: { sub: data.userId },
			})

			await this.prismaService.userAuth.deleteMany({
				where: { baseUserId: data.userId },
			})

			console.log(`Successfully deleted auth data for user ${data.userId}`)
			return this.ack(context)
		} catch (error) {
			console.error('Failed to delete auth data:', error)
			return this.nack(context)
		}
	}
}
