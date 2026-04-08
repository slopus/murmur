-- CreateTable
CREATE TABLE "Feed" (
    "id" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "metadata" BYTEA NOT NULL,
    "currentEpoch" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Feed_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FeedMember" (
    "id" TEXT NOT NULL,
    "feedId" TEXT NOT NULL,
    "memberId" TEXT NOT NULL,
    "epoch" INTEGER NOT NULL,
    "encryptedKey" BYTEA NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FeedMember_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FeedItem" (
    "id" TEXT NOT NULL,
    "feedId" TEXT NOT NULL,
    "authorId" TEXT NOT NULL,
    "epoch" INTEGER NOT NULL,
    "blob" BYTEA NOT NULL,
    "signature" BYTEA NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FeedItem_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Feed_ownerId_updatedAt_idx" ON "Feed"("ownerId", "updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "FeedMember_feedId_memberId_epoch_key" ON "FeedMember"("feedId", "memberId", "epoch");

-- CreateIndex
CREATE INDEX "FeedMember_memberId_feedId_idx" ON "FeedMember"("memberId", "feedId");

-- CreateIndex
CREATE INDEX "FeedMember_feedId_epoch_idx" ON "FeedMember"("feedId", "epoch");

-- CreateIndex
CREATE INDEX "FeedItem_feedId_createdAt_idx" ON "FeedItem"("feedId", "createdAt");

-- CreateIndex
CREATE INDEX "FeedItem_createdAt_idx" ON "FeedItem"("createdAt");

-- CreateIndex
CREATE INDEX "FeedItem_authorId_idx" ON "FeedItem"("authorId");

-- AddForeignKey
ALTER TABLE "Feed" ADD CONSTRAINT "Feed_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FeedMember" ADD CONSTRAINT "FeedMember_feedId_fkey" FOREIGN KEY ("feedId") REFERENCES "Feed"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FeedMember" ADD CONSTRAINT "FeedMember_memberId_fkey" FOREIGN KEY ("memberId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FeedItem" ADD CONSTRAINT "FeedItem_feedId_fkey" FOREIGN KEY ("feedId") REFERENCES "Feed"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FeedItem" ADD CONSTRAINT "FeedItem_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
