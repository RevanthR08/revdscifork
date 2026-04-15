/** @type {import('next').NextConfig} */
const path = require('path')

const nextConfig = {
  reactStrictMode: true,
  turbopack: {
    root: path.resolve(__dirname, '.'),
  },
  allowedDevOrigins: process.env.ALLOWED_DEV_ORIGINS
    ? process.env.ALLOWED_DEV_ORIGINS.split(',')
    : [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://10.195.171.144:3000',
      ],
}

module.exports = nextConfig
