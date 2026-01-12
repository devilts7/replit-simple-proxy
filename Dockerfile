FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*. json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY server.js . 
COPY public/ ./public/

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT || 3000) + '/health', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"

# Expose port
EXPOSE ${PORT:-3000}

# Run server
CMD ["npm", "start"]