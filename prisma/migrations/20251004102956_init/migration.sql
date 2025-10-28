-- CreateTable
CREATE TABLE "jwt_refresh_token" (
    "jti" SERIAL NOT NULL,
    "sub" INTEGER NOT NULL,
    "revoked" BOOLEAN NOT NULL,
    "exp" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "jwt_refresh_token_pkey" PRIMARY KEY ("jti")
);

-- CreateIndex
CREATE UNIQUE INDEX "jwt_refresh_token_sub_key" ON "jwt_refresh_token"("sub");
