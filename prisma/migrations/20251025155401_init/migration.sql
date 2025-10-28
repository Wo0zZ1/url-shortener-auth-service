/*
  Warnings:

  - You are about to drop the column `createadAt` on the `jwt_refresh_token` table. All the data in the column will be lost.
  - Added the required column `iat` to the `jwt_refresh_token` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "jwt_refresh_token" DROP COLUMN "createadAt",
ADD COLUMN     "iat" TIMESTAMP(3) NOT NULL;
