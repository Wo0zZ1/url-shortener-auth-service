export interface UserAuthEntity {
	id?: number
	baseUserId: number
	login: string
	hashPassword: string
	passwordUpdatedAt?: Date
}
