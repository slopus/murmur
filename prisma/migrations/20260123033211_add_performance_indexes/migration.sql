-- CreateIndex
CREATE INDEX "Message_recipientId_deliveredAt_idx" ON "Message"("recipientId", "deliveredAt");

-- CreateIndex
CREATE INDEX "Message_recipientId_createdAt_expiresAt_idx" ON "Message"("recipientId", "createdAt", "expiresAt");
