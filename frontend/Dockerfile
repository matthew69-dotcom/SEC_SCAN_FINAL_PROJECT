# Frontend — production image: build with Node, serve with nginx.
# nginx also reverse-proxies /api/* to the backend container, so the
# browser talks to a single origin (no CORS issues).
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
# npm ci inside Linux installs the correct rolldown/vite native binding —
# the "vite build fails on Linux" issue only affects reusing Windows node_modules.
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
