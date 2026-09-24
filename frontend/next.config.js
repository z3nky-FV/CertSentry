/** @type {import('next').NextConfig} */
const backendUrl = (process.env.CERTSENTRY_API_URL || 'http://localhost:8000').replace(/\/$/, '');

const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
};
module.exports = nextConfig;
