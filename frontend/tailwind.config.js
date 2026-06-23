/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      colors: {
        surface: {
          DEFAULT: "#0b0e18",
          card:    "#0f1420",
          raised:  "#131826",
          border:  "#1c2438",
        },
      },
      boxShadow: {
        glow:    "0 0 20px -4px rgba(34,211,238,0.25)",
        "glow-g":"0 0 20px -4px rgba(52,211,153,0.25)",
        "glow-r":"0 0 20px -4px rgba(239,68,68,0.25)",
      },
      animation: {
        "ping-slow": "ping-slow 2.2s cubic-bezier(0,0,0.2,1) infinite",
        "fade-up":   "fade-up 0.35s ease both",
        scanline:    "scanline 2.8s linear infinite",
      },
    },
  },
  plugins: [],
};
