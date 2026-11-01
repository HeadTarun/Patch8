import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return process.env.NODE_ENV === "development" ? [{ source: "/api/:path*", destination: `${process.env.API_ORIGIN || "http://localhost:8000"}/api/:path*` }] : [];
  },
  typescript: { tsconfigPath: "tsconfig.next.json" },
  webpack(config) {
    config.resolve.conditionNames = [...new Set([...(config.resolve.conditionNames ?? []), "import"] )];
    return config;
  },
};
export default nextConfig;
