import {
	Injectable,
	CanActivate,
	ExecutionContext,
	UnauthorizedException,
} from '@nestjs/common'
import { type Request } from 'express'

import { AuthService } from '../auth.service'
import { AccessTokenPayload } from '@wo0zz1/url-shortener-shared'

export const ACCESS_PAYLOAD = 'accessPayload'

@Injectable()
export class AccessTokenGuard implements CanActivate {
	constructor(private readonly authService: AuthService) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest<Request>()

		const token = this.extractTokenFromHeader(request)

		if (!token)
			throw new UnauthorizedException('Access token not found in Authorization header')

		try {
			const payload: AccessTokenPayload =
				await this.authService.validateAccessToken(token)
			request[ACCESS_PAYLOAD] = payload
			return true
		} catch {
			throw new UnauthorizedException('Invalid access token')
		}
	}

	private extractTokenFromHeader(request: Request): string | undefined {
		const [type, token] = request.headers.authorization?.split(' ') ?? []
		return type === 'Bearer' ? token : undefined
	}
}
