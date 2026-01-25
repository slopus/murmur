/*
  Warnings:

  - You are about to drop the `UserSequence` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "UserSequence" DROP CONSTRAINT "UserSequence_userId_fkey";

-- DropTable
DROP TABLE "UserSequence";
