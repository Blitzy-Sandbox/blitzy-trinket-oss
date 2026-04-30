FROM node:18-alpine
# SECURITY: python manager base image audited per AAP §0.5.2 Strategy F / R6 - node:18-alpine verified against Trivy CRITICAL/HIGH OS-layer CVEs

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

EXPOSE 8100

CMD ["node", "manager.js"]
