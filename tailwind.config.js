/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          primary: '#00ff41',
          secondary: '#ff0080',
          accent: '#00d4ff',
          warning: '#ffaa00',
          danger: '#ff0040',
          dark: '#0a0a0a',
          darker: '#050505',
          grid: '#1a1a1a',
        },
      },
      fontFamily: {
        cyber: ['Orbitron', 'monospace'],
        'cyber-alt': ['Rajdhani', 'monospace'],
        'cyber-mono': ['Share Tech Mono', 'monospace'],
      },
      boxShadow: {
        'cyber-sm': '0 0 10px rgba(0, 255, 65, 0.3)',
        'cyber-md': '0 0 20px rgba(0, 255, 65, 0.4)',
        'cyber-lg': '0 0 30px rgba(0, 255, 65, 0.5)',
        'cyber-xl': '0 0 50px rgba(0, 255, 65, 0.6)',
        'cyber-inner': 'inset 0 0 20px rgba(0, 255, 65, 0.3)',
        'cyber-danger-sm': '0 0 10px rgba(255, 0, 64, 0.3)',
        'cyber-danger-md': '0 0 20px rgba(255, 0, 64, 0.4)',
        'cyber-danger-lg': '0 0 30px rgba(255, 0, 64, 0.5)',
        'cyber-accent-sm': '0 0 10px rgba(0, 212, 255, 0.3)',
        'cyber-accent-md': '0 0 20px rgba(0, 212, 255, 0.4)',
        'cyber-accent-lg': '0 0 30px rgba(0, 212, 255, 0.5)',
      },
      animation: {
        'cyber-pulse': 'cyber-pulse 2s infinite alternate',
        'cyber-scan': 'cyber-scan 3s linear infinite',
        'cyber-glitch': 'cyber-glitch 1s infinite linear alternate-reverse',
        'cyber-float': 'cyber-float 3s ease-in-out infinite alternate',
        'cyber-data': 'cyber-data 10s linear infinite',
        'cyber-rotate': 'cyber-rotate 10s linear infinite',
        'cyber-blink': 'cyber-blink 1s step-end infinite',
      },
      keyframes: {
        'cyber-pulse': {
          '0%': { opacity: 0.7, boxShadow: '0 0 10px rgba(0, 255, 65, 0.3)' },
          '100%': { opacity: 1, boxShadow: '0 0 30px rgba(0, 255, 65, 0.6)' },
        },
        'cyber-scan': {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
        'cyber-glitch': {
          '0%': { transform: 'translate(0)' },
          '20%': { transform: 'translate(-2px, 2px)' },
          '40%': { transform: 'translate(-2px, -2px)' },
          '60%': { transform: 'translate(2px, 2px)' },
          '80%': { transform: 'translate(2px, -2px)' },
          '100%': { transform: 'translate(0)' },
        },
        'cyber-float': {
          '0%': { transform: 'translateY(0)' },
          '100%': { transform: 'translateY(-10px)' },
        },
        'cyber-data': {
          '0%': { backgroundPosition: '0 0' },
          '100%': { backgroundPosition: '0 100px' },
        },
        'cyber-rotate': {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        'cyber-blink': {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0 },
        },
      },
      backgroundImage: {
        'cyber-grid': 'linear-gradient(rgba(0, 255, 65, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 65, 0.1) 1px, transparent 1px)',
        'cyber-gradient': 'linear-gradient(45deg, rgba(0, 255, 65, 0.1) 0%, rgba(0, 212, 255, 0.1) 100%)',
        'cyber-radial': 'radial-gradient(circle at center, rgba(0, 255, 65, 0.1) 0%, transparent 70%)',
        'cyber-danger-grid': 'linear-gradient(rgba(255, 0, 64, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 0, 64, 0.1) 1px, transparent 1px)',
        'cyber-danger-gradient': 'linear-gradient(45deg, rgba(255, 0, 64, 0.1) 0%, rgba(255, 170, 0, 0.1) 100%)',
        'cyber-danger-radial': 'radial-gradient(circle at center, rgba(255, 0, 64, 0.1) 0%, transparent 70%)',
      },
      backdropFilter: {
        'cyber': 'blur(10px)',
      },
      textShadow: {
        'cyber-sm': '0 0 5px var(--cyber-primary)',
        'cyber-md': '0 0 10px var(--cyber-primary)',
        'cyber-lg': '0 0 15px var(--cyber-primary)',
        'cyber-xl': '0 0 20px var(--cyber-primary)',
      },
    },
  },
  plugins: [],
};