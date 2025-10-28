import {
	Injectable,
	CanActivate,
	ExecutionContext,
	UnauthorizedException,
} from '@nestjs/common'
import { type Request } from 'express'

import { AuthService } from '../auth.service'

export const REFRESH_PAYLOAD = 'refreshPayload'

@Injectable()
export class RefreshTokenGuard implements CanActivate {
	constructor(private readonly authService: AuthService) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest<Request>()

		const token = request.body?.refreshToken as string | undefined

		if (!token) throw new UnauthorizedException('Refresh token not found in request body')

		try {
			const payload = await this.authService.validateRefreshToken(token)
			request[REFRESH_PAYLOAD] = payload
			return true
		} catch {
			throw new UnauthorizedException('Invalid refresh token')
		}
	}
}
