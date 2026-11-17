FROM node:20-alpine

WORKDIR /app

# Copy root configuration
COPY package*.json ./
COPY backend/package*.json ./backend/
COPY frontend/package*.json ./frontend/

# Install dependencies
RUN npm --prefix backend install --omit=dev
RUN npm --prefix frontend install

# Copy source
COPY . .

# Build frontend production bundle
RUN npm --prefix frontend run build

EXPOSE 5001

ENV NODE_ENV=production
ENV PORT=5001

CMD ["npm", "start"]
