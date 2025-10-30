import { EventQueue, getMicroserviceConfig } from '@wo0zz1/url-shortener-shared'
import { NestFactory } from '@nestjs/core'
import cookieParser from 'cookie-parser'

import { ValidationPipe } from '@nestjs/common'
import { AppModule } from './app.module'

async function bootstrap() {
	const PORT = process.env.PORT
	if (!PORT) throw new Error('PORT env isnt configured')
	const RABBITMQ_URL = process.env.RABBITMQ_URL
	if (!RABBITMQ_URL) throw new Error('RABBITMQ_URL env isnt configured')

	const app = await NestFactory.create(AppModule)

	app.useGlobalPipes(
		new ValidationPipe({
			transform: true,
			whitelist: true,
			forbidNonWhitelisted: true,
		}),
	)

	app.use(cookieParser())
	app.enableCors()

	await app.listen(PORT)

	console.log(`🚀 Auth Service is running on: http://localhost:${PORT}`)

	try {
		app.connectMicroservice(getMicroserviceConfig(RABBITMQ_URL, EventQueue.AUTH_SERVICE))
		await app.startAllMicroservices()
		console.log('Auth Service started with RabbitMQ')
	} catch (error) {
		console.error('Failed to connect to RabbitMQ:', error)
		console.log('Service will continue running without RabbitMQ connection')
	}
}

bootstrap().catch(error => {
	console.error('Failed to start application:', error)
	process.exit(1)
})
