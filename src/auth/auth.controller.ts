import {
	Controller,
	Post,
	Body,
	HttpCode,
	HttpStatus,
	UseGuards,
	Delete,
	Get,
	Param,
	ParseIntPipe,
	Headers,
} from '@nestjs/common'

import {
	GatewaySecretGuard,
	LoginDto,
	LoginResponse,
	LogoutResponse,
	LogoutAllResponse,
	GetActiveSessionsResponse,
	RevokeSessionResponse,
	DeleteUserResponse,
	RefreshTokenResponse,
	RegisterGuestResponse,
	RegisterUserDto,
	RegisterUserResponse,
	type AccessTokenPayload,
	type GetCurrentUserResponse,
} from '@wo0zz1/url-shortener-shared'

import { AuthService } from './auth.service'

import { AccessTokenGuard } from './guards'

import { CurrentAccessTokenPayload } from './decorators'
import { LogoutDto, RefreshTokenDto } from './dto'

@Controller('auth')
@UseGuards(GatewaySecretGuard)
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	@Post('register-guest')
	async registerGuest(): Promise<RegisterGuestResponse> {
		return await this.authService.registerGuest()
	}

	@Post('register-user')
	async register(
		@Body() registerDto: RegisterUserDto,
		@Headers('x-guest-uuid') guestUuid?: string,
	): Promise<RegisterUserResponse> {
		return await this.authService.registerUser(registerDto, guestUuid)
	}

	@Post('login')
	@HttpCode(HttpStatus.OK)
	async login(
		@Body() loginDto: LoginDto,
		@Headers('x-guest-uuid') guestUuid?: string,
	): Promise<LoginResponse> {
		return await this.authService.login(loginDto, guestUuid)
	}

	@Post('refresh')
	@HttpCode(HttpStatus.OK)
	async refresh(@Body() refreshTokenDto: RefreshTokenDto): Promise<RefreshTokenResponse> {
		return await this.authService.refreshTokens(refreshTokenDto.refreshToken)
	}

	@Post('logout')
	@HttpCode(HttpStatus.OK)
	async logout(@Body() logoutDto: LogoutDto): Promise<LogoutResponse> {
		await this.authService.logout(logoutDto.refreshToken)
		return { message: 'Logged out successfully' }
	}

	@Post('logout-all')
	@HttpCode(HttpStatus.OK)
	async logoutAll(@Body() logoutDto: LogoutDto): Promise<LogoutAllResponse> {
		await this.authService.logoutAll(logoutDto.refreshToken)
		return { message: 'Logged out from all devices successfully' }
	}

	@Get('me')
	@UseGuards(AccessTokenGuard)
	getCurrentUser(
		@CurrentAccessTokenPayload() accessTokenPayload: AccessTokenPayload,
	): GetCurrentUserResponse {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { iat, exp, ...userData } = accessTokenPayload
		return userData
	}

	@Get('user/:userId/sessions')
	async getActiveSessions(
		@Param('userId', ParseIntPipe) userId: number,
	): Promise<GetActiveSessionsResponse> {
		return this.authService.getActiveSessions(userId)
	}

	@Delete('user/:userId/sessions/:jti')
	async revokeSession(
		@Param('userId', ParseIntPipe) userId: number,
		@Param('jti', ParseIntPipe) jti: number,
	): Promise<RevokeSessionResponse> {
		await this.authService.revokeSession(userId, jti)
		return { message: 'Session revoked' }
	}

	@Delete('user/:userId')
	@HttpCode(HttpStatus.OK)
	async deleteUser(
		@Param('userId', ParseIntPipe) userId: number,
	): Promise<DeleteUserResponse> {
		await this.authService.deleteUser(userId)
		return { message: 'Deletion initiated' }
	}
}
