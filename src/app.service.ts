import { Injectable } from '@nestjs/common'
import { PrismaService } from './prisma/prisma.service'

@Injectable()
export class AppService {
	constructor(private readonly prismaService: PrismaService) {}

	async healthCheck() {
		try {
			await this.prismaService.$queryRaw`SELECT 1`
			return 'OK'
		} catch {
			return { errors: [{ message: 'Database disconnected' }] }
		}
	}
}
