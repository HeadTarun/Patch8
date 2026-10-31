import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  typescript: { tsconfigPath: "tsconfig.next.json" },
  webpack(config) {
    config.resolve.conditionNames = [...new Set([...(config.resolve.conditionNames ?? []), "import"] )];
    return config;
  },
};
export default nextConfig;
