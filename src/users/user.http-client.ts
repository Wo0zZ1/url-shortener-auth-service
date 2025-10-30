import { Injectable, HttpException, HttpStatus, ConflictException } from '@nestjs/common'
import { HttpService } from '@nestjs/axios'
import { firstValueFrom } from 'rxjs'

import {
	CreateUserDto,
	CreateUserResponse,
	GetUserByIdResponse,
	GetUserByUuidResponse,
	UpdateUserDto,
	UserEntity,
	UserHeaders,
} from '@wo0zz1/url-shortener-shared'

@Injectable()
export class UsersHttpClient {
	private readonly baseUrl: string
	private readonly gatewaySecret: string

	constructor(private readonly httpService: HttpService) {
		if (!process.env.USER_SERVICE_URL)
			throw new Error('Env not configured: missed USER_SERVICE_URL')
		this.baseUrl = process.env.USER_SERVICE_URL

		if (!process.env.API_GATEWAY_SECRET)
			throw new Error('Env not configured: missed API_GATEWAY_SECRET')
		this.gatewaySecret = process.env.API_GATEWAY_SECRET
	}

	private getGatewayHeaders(userHeaders?: UserHeaders) {
		return {
			'x-api-gateway-secret': this.gatewaySecret,
			...userHeaders,
		}
	}

	async create(createUserDto: CreateUserDto): Promise<UserEntity> {
		try {
			const response = await firstValueFrom(
				this.httpService.post<CreateUserResponse>(
					`${this.baseUrl}/users`,
					createUserDto,
					{ headers: this.getGatewayHeaders() },
				),
			)
			const user = response.data

			return user
		} catch (error) {
			if (error.response?.status === 409)
				throw new ConflictException('User with this login already exists')
			throw error
		}
	}

	async patch(userId: number, updateUserDto: UpdateUserDto): Promise<UserEntity> {
		try {
			const response = await firstValueFrom(
				this.httpService.patch<UserEntity>(
					`${this.baseUrl}/users/id/${userId}`,
					updateUserDto,
					{ headers: this.getGatewayHeaders() },
				),
			)
			const updatedUser = response.data

			return updatedUser
		} catch (error) {
			if (error.response?.status === 409)
				throw new ConflictException('User with this login already exists')
			throw error
		}
	}

	async findById(id: number): Promise<UserEntity | null> {
		try {
			const response = await firstValueFrom(
				this.httpService.get<GetUserByIdResponse>(`${this.baseUrl}/users/id/${id}`, {
					headers: this.getGatewayHeaders(),
				}),
			)

			const user = response.data

			return user
		} catch (error) {
			if (error.response?.status === 404) return null
			throw new HttpException('User service unavailable', HttpStatus.SERVICE_UNAVAILABLE)
		}
	}

	async findByUUID(uuid: string): Promise<UserEntity | null> {
		try {
			const response = await firstValueFrom(
				this.httpService.get<GetUserByUuidResponse>(
					`${this.baseUrl}/users/uuid/${uuid}`,
					{ headers: this.getGatewayHeaders() },
				),
			)
			const user = response.data

			return user
		} catch (error) {
			if (error.response?.status === 404) return null
			throw new HttpException('User service unavailable', HttpStatus.SERVICE_UNAVAILABLE)
		}
	}
}
