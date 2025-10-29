FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile

COPY . .

RUN npx prisma generate

RUN yarn build

RUN yarn workspaces focus --production || yarn install --production --frozen-lockfile --ignore-scripts --prefer-offline

FROM node:22-alpine AS production

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/package.json ./package.json

CMD ["sh", "-c", "npx prisma migrate deploy && node dist/main"]