import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // A small named palette keeps component classes readable and makes a
        // future theme change a one-file edit.
        surface: {
          DEFAULT: "#0b1020",
          raised: "#141a2e",
          border: "#242c45",
        },
        accent: {
          DEFAULT: "#6366f1",
          soft: "#818cf8",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
