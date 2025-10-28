import {
	createParamDecorator,
	ExecutionContext,
	UnauthorizedException,
} from '@nestjs/common'
import { type Request } from 'express'

import { ACCESS_PAYLOAD } from '../guards'

export const CurrentAccessTokenPayload = createParamDecorator(
	(data: unknown, context: ExecutionContext) => {
		const request = context.switchToHttp().getRequest<Request>()
		const user = request[ACCESS_PAYLOAD]

		if (!user) throw new UnauthorizedException('User not authenticated')

		return user
	},
)
