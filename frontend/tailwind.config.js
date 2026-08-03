/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0b0f19', // Dark primary slate-950/custom
          card: '#111827', // Slate-900 / custom
          border: '#1f2937', // Gray-800
          accent: '#06b6d4', // Cyan
          blue: '#2563eb', // Blue
          red: '#dc2626', // Red
          yellow: '#d97706', // Amber/Yellow
          green: '#16a34a', // Green
          text: '#9ca3af' // Slate-400
        }
      }
    },
  },
  plugins: [],
}
