-- CreateTable
CREATE TABLE "user_auth" (
    "id" SERIAL NOT NULL,
    "baseUserId" INTEGER NOT NULL,
    "login" TEXT NOT NULL,
    "hashPassword" TEXT NOT NULL,
    "passwordUpdatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_auth_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_auth_baseUserId_key" ON "user_auth"("baseUserId");

-- CreateIndex
CREATE UNIQUE INDEX "user_auth_login_key" ON "user_auth"("login");
