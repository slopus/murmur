-- CreateTable
CREATE TABLE "PreKey" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ownerId" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "signature" BYTEA NOT NULL,
    "oneTime" BOOLEAN NOT NULL,
    "allocatedTo" TEXT,
    "allocatedAt" TIMESTAMP(3),

    CONSTRAINT "PreKey_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PreKey_ownerId_oneTime_allocatedTo_idx" ON "PreKey"("ownerId", "oneTime", "allocatedTo");

-- CreateIndex
CREATE INDEX "PreKey_ownerId_oneTime_idx" ON "PreKey"("ownerId", "oneTime");

-- AddForeignKey
ALTER TABLE "PreKey" ADD CONSTRAINT "PreKey_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PreKey" ADD CONSTRAINT "PreKey_allocatedTo_fkey" FOREIGN KEY ("allocatedTo") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
