/*
  Warnings:

  - Changed the type of `blob` on the `Message` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Changed the type of `signature` on the `Message` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Made the column `profilePublicKey` on table `User` required. This step will fail if there are existing NULL values in that column.
  - Added the required column `profileKeySignature` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `encryptedProfile` to the `User` table without a default value. This is not possible if the table is not empty.
  - Made the column `profileUpdatedAt` on table `User` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "Message" DROP COLUMN "blob",
ADD COLUMN     "blob" BYTEA NOT NULL,
DROP COLUMN "signature",
ADD COLUMN     "signature" BYTEA NOT NULL;

-- AlterTable
ALTER TABLE "User" ALTER COLUMN "profilePublicKey" SET NOT NULL,
DROP COLUMN "profileKeySignature",
ADD COLUMN     "profileKeySignature" BYTEA NOT NULL,
DROP COLUMN "encryptedProfile",
ADD COLUMN     "encryptedProfile" BYTEA NOT NULL,
ALTER COLUMN "profileUpdatedAt" SET NOT NULL,
ALTER COLUMN "profileUpdatedAt" SET DEFAULT CURRENT_TIMESTAMP;
