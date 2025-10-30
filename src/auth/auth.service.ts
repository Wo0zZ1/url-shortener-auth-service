import {
	ConflictException,
	Injectable,
	UnauthorizedException,
	ForbiddenException,
	NotFoundException,
	Inject,
	OnModuleInit,
} from '@nestjs/common'
import * as bcrypt from 'bcrypt'
import { randomUUID } from 'crypto'
import { JwtService, JwtSignOptions } from '@nestjs/jwt'
import { ClientProxy } from '@nestjs/microservices'
import {
	AccessTokenPayload,
	EEventPattern,
	LoginDto,
	LoginResponse,
	MigrateGuestDto,
	RefreshTokenResponse,
	RegisterGuestResponse,
	RegisterUserDto,
	RegisterUserResponse,
	GetActiveSessionsResponse,
	Tokens,
	UserAccountsMergedEvent,
	UserEntity,
	UserType,
	CreateAccessTokenPayload,
	CreateRefreshTokenPayload,
	RefreshTokenPayload,
	EVENT_EMITTER_NAME,
	UserDeletedEvent,
} from '@wo0zz1/url-shortener-shared'

import { UsersHttpClient } from '../users/user.http-client'

import { UserAuthEntity } from './entities'
import { PrismaService } from 'src/prisma/prisma.service'

@Injectable()
export class AuthService implements OnModuleInit {
	private readonly refreshTokenExpiresIn: number
	private readonly accessTokenExpiresIn: number
	private readonly gatewaySecret: string

	constructor(
		private readonly usersClient: UsersHttpClient,
		private readonly jwtService: JwtService,
		private readonly prismaService: PrismaService,
		@Inject(EVENT_EMITTER_NAME) private readonly eventEmitter: ClientProxy,
	) {
		const accessExpiresInString = process.env.JWT_ACCESS_EXPIRES_IN
		if (!accessExpiresInString)
			throw new Error('JWT_ACCESS_EXPIRES_IN env isnt configured')
		this.accessTokenExpiresIn = this.parseExpiresIn(accessExpiresInString)

		const refreshExpiresInString = process.env.JWT_REFRESH_EXPIRES_IN
		if (!refreshExpiresInString)
			throw new Error('JWT_REFRESH_EXPIRES_IN env isnt configured')
		this.refreshTokenExpiresIn = this.parseExpiresIn(refreshExpiresInString)
	}

	async onModuleInit() {
		await Promise.all([this.eventEmitter.connect()])
	}

	async validateUser(login: string, password: string): Promise<UserEntity> {
		const existingAuth = await this.getUserAuthByLogin(login)
		if (!existingAuth) throw new UnauthorizedException('Invalid credentials')

		const user = await this.usersClient.findById(existingAuth.baseUserId)
		if (!user) throw new UnauthorizedException('Invalid credentials')

		const isPasswordValid = await bcrypt.compare(password, existingAuth.hashPassword)
		if (!isPasswordValid) throw new UnauthorizedException('Invalid credentials')

		return user
	}

	async registerGuest(): Promise<RegisterGuestResponse> {
		const uuid = randomUUID()

		const createdUser = await this.usersClient.create({
			type: 'Guest',
			uuid,
		})

		return { createdUser }
	}

	async registerUser(
		registerDto: RegisterUserDto,
		guestUuid?: string,
	): Promise<RegisterUserResponse> {
		const { login, password, ...createUserDto } = registerDto

		const existingAuth = await this.getUserAuthByLogin(login)
		if (existingAuth) throw new ConflictException('User with this login already exists')

		let createdUser: UserEntity

		if (guestUuid) createdUser = await this.migrateAccount(guestUuid, registerDto)
		else createdUser = await this.usersClient.create(createUserDto)

		const hashPassword = await bcrypt.hash(password, 12)

		try {
			await this.prismaService.userAuth.create({
				data: { baseUserId: createdUser.id, login, hashPassword },
			})
		} catch (error) {
			this.eventEmitter.emit(EEventPattern.USER_DELETED, { userId: createdUser.id })
			throw error
		}

		const tokens = await this.generateTokens(createdUser.id, createdUser.type)

		return { createdUser, tokens }
	}

	async migrateAccount(
		guestUuid: string,
		migrateGuestDto: MigrateGuestDto,
	): Promise<UserEntity> {
		const guestEntity = await this.usersClient.findByUUID(guestUuid)

		if (!guestEntity) throw new NotFoundException('Guest user not found')

		const { userProfile } = migrateGuestDto

		const userEntity = await this.usersClient.patch(guestEntity.id, {
			type: 'User',
			uuid: null,
			userProfile: userProfile,
		})

		return userEntity
	}

	mergeAccountsData(sourceEntityId: number, targetEntityId: number): void {
		const accountsMergedEvent: UserAccountsMergedEvent = {
			sourceUserId: sourceEntityId,
			targetUserId: targetEntityId,
			timestamp: new Date(),
		}
		this.eventEmitter.emit(EEventPattern.USER_ACCOUNTS_MERGED, accountsMergedEvent)
		console.log(
			`Emitted ${EEventPattern.USER_ACCOUNTS_MERGED} with data:`,
			accountsMergedEvent,
		)
	}

	async login(loginDto: LoginDto, guestUuid?: string): Promise<LoginResponse> {
		const user = await this.validateUser(loginDto.login, loginDto.password)

		if (guestUuid) {
			const guestUser = await this.usersClient.findByUUID(guestUuid)

			if (!guestUser) console.error('Error in guest migration: Guest not found')
			else if (user.userProfile) this.mergeAccountsData(guestUser.id, user.id)
		}

		const tokens = await this.generateTokens(
			user.id,
			user.type,
			user.type === 'Guest' && user.uuid ? user.uuid : undefined,
		)

		void this.cleanupOldTokens(user.id) // TODO: переделать на событие

		const tokenPayload = await this.validateAccessToken(tokens.accessToken)

		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { exp, iat, ...userPayload } = tokenPayload

		return { user: userPayload, tokens }
	}

	async refreshTokens(refreshToken: string): Promise<RefreshTokenResponse> {
		const payload = await this.validateRefreshToken(refreshToken)

		const deletedToken = await this.prismaService.jwtRefreshToken.deleteMany({
			where: {
				jti: payload.jti,
				revoked: false,
				exp: { gt: new Date() },
			},
		})

		if (deletedToken.count === 0)
			throw new ForbiddenException('Invalid or expired refresh token')

		const user = await this.usersClient.findById(payload.sub)
		if (!user) throw new ForbiddenException('User not found')

		// Для Guest пользователей передаем uuid в токен
		const newTokens = await this.generateTokens(
			user.id,
			user.type,
			user.type === 'Guest' && user.uuid ? user.uuid : undefined,
		)

		void this.cleanupOldTokens(payload.sub)

		return newTokens
	}

	async logout(refreshToken: string): Promise<void> {
		try {
			const payload = await this.validateRefreshToken(refreshToken)

			await this.prismaService.jwtRefreshToken.updateMany({
				where: { jti: payload.jti, revoked: false, exp: { gt: new Date() } },
				data: { revoked: true },
			})
		} catch (error) {
			// Ignore invalid token error - allow silent logout
			if (error instanceof UnauthorizedException) return
			console.error('Logout error:', error)
		}
	}

	async logoutAll(refreshToken: string): Promise<void> {
		try {
			const payload = await this.validateRefreshToken(refreshToken)

			await this.prismaService.jwtRefreshToken.updateMany({
				where: {
					sub: payload.sub,
					revoked: false,
					exp: { gt: new Date() },
				},
				data: { revoked: true },
			})
		} catch (error) {
			// Ignore invalid token error - allow silent logout
			if (error instanceof UnauthorizedException) return
			console.error('Logout-all error:', error)
		}
	}

	private async cleanupOldTokens(userId: number): Promise<void> {
		await this.prismaService.jwtRefreshToken.deleteMany({
			where: {
				sub: userId,
				revoked: false,
				exp: { lte: new Date() },
			},
		})
	}

	private async generateTokens(
		userId: number,
		userType: UserType,
		uuid?: string,
	): Promise<Tokens> {
		const [accessToken, refreshToken] = await Promise.all([
			this.generateAccessToken(userId, userType, uuid),
			this.generateRefreshToken(userId),
		])

		return { accessToken, refreshToken }
	}

	private async generateAccessToken(
		userId: number,
		userType: UserType,
		uuid?: string,
	): Promise<string> {
		const payload: CreateAccessTokenPayload = {
			sub: userId,
			type: userType,
			...(uuid && { uuid }),
		}

		const accessTokenString = await this.jwtService.signAsync(payload, {
			secret: process.env.JWT_ACCESS_SECRET,
			expiresIn: process.env.JWT_ACCESS_EXPIRES_IN as JwtSignOptions['expiresIn'],
		})

		return accessTokenString
	}

	private async generateRefreshToken(userId: number): Promise<string> {
		const refreshToken = await this.prismaService.jwtRefreshToken.create({
			data: {
				sub: userId,
				iat: new Date(),
				exp: new Date(Date.now() + this.refreshTokenExpiresIn),
			},
		})

		const payload: CreateRefreshTokenPayload = {
			sub: refreshToken.sub,
			jti: refreshToken.jti,
			revoked: refreshToken.revoked,
		}

		const refreshTokenString = await this.jwtService.signAsync(payload, {
			secret: process.env.JWT_REFRESH_SECRET,
		})

		return refreshTokenString
	}

	async validateAccessToken(token: string): Promise<AccessTokenPayload> {
		try {
			const accessTokenPayload = await this.jwtService.verifyAsync<AccessTokenPayload>(
				token,
				{ secret: process.env.JWT_ACCESS_SECRET },
			)

			return accessTokenPayload
		} catch {
			throw new UnauthorizedException('Invalid access token')
		}
	}

	async validateRefreshToken(token: string): Promise<RefreshTokenPayload> {
		try {
			const refreshTokenPayload = await this.jwtService.verifyAsync<RefreshTokenPayload>(
				token,
				{ secret: process.env.JWT_REFRESH_SECRET },
			)

			return refreshTokenPayload
		} catch {
			throw new UnauthorizedException('Invalid refresh token')
		}
	}

	async getActiveSessions(userId: number): Promise<GetActiveSessionsResponse> {
		return await this.prismaService.jwtRefreshToken.findMany({
			where: {
				sub: userId,
				revoked: false,
				exp: { gt: new Date() },
			},
			orderBy: { iat: 'desc' },
		})
	}

	async revokeSession(userId: number, jti: number): Promise<void> {
		try {
			await this.prismaService.jwtRefreshToken.update({
				where: { jti, sub: userId },
				data: { revoked: true },
			})
		} catch (error) {
			if (error.code === 'P2025') throw new NotFoundException('Session not found')
			throw error
		}
	}

	async deleteUser(userId: number): Promise<void> {
		// Проверяем существование пользователя
		const userAuth = await this.prismaService.userAuth.findUnique({
			where: { baseUserId: userId },
		})

		if (!userAuth) {
			throw new NotFoundException('User authentication data not found')
		}

		// Отправляем событие USER_DELETED
		// Auth-service сам обработает это событие и удалит свои данные
		const userDeletedEvent: UserDeletedEvent = {
			userId,
			timestamp: new Date(),
		}
		this.eventEmitter.emit(EEventPattern.USER_DELETED, userDeletedEvent)
		console.log(`Emitted ${EEventPattern.USER_DELETED} with data:`, userDeletedEvent)
	}

	async getUserAuthByLogin(
		login: UserAuthEntity['login'],
	): Promise<UserAuthEntity | null> {
		return await this.prismaService.userAuth.findUnique({ where: { login } })
	}

	private parseExpiresIn(expiresIn: string): number {
		const match = expiresIn.match(/^(\d+)([smhd])$/)
		if (!match) throw new Error('Invalid expiresIn pattern')

		const [, value, unit] = match
		const numValue = parseInt(value)

		switch (unit) {
			case 's':
				return numValue * 1000
			case 'm':
				return numValue * 60 * 1000
			case 'h':
				return numValue * 60 * 60 * 1000
			case 'd':
				return numValue * 24 * 60 * 60 * 1000
			default:
				return numValue * 1000
		}
	}
}
