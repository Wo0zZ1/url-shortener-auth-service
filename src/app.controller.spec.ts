import { Test, TestingModule } from '@nestjs/testing'

import { PrismaModule } from './prisma/prisma.module'

import { AppController } from './app.controller'

import { AppService } from './app.service'

describe('AppController', () => {
	let appController: AppController

	beforeEach(async () => {
		const app: TestingModule = await Test.createTestingModule({
			imports: [PrismaModule],
			controllers: [AppController],
			providers: [AppService],
		}).compile()

		appController = app.get<AppController>(AppController)
	})

	describe('root', () => {
		it('should return "OK"', async () => {
			expect(await appController.healthCheck()).toBe('OK')
		})
	})
})
