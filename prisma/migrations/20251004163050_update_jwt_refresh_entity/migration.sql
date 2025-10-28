-- CreateIndex
CREATE INDEX "jwt_refresh_token_sub_revoked_idx" ON "jwt_refresh_token"("sub", "revoked");
