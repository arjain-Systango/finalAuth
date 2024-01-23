# Stage 1: Build

# Use a smaller Node.js base image
FROM node:18-alpine AS build

# Set the working directory in the container
WORKDIR /src

# Copy package.json and package-lock.json to the container
COPY package*.json ./

# Install dependencies and remove unnecessary files in the same layer to reduce cache size
RUN npm install && \
    npm cache clean --force && \
    rm -rf /root/.npm

# Copy the application code to the container
COPY . .

# Create Build
RUN npm run build

# Stage 2: Production

# Use a smaller base image for the final stage
FROM node:18-alpine AS production

# Set the working directory in the final image
WORKDIR /app

# Copy only necessary files from the build stage
COPY --from=build /src /app

# Expose a port that the application will listen on
EXPOSE 3007

# Run the final image
CMD ["npm", "start"]