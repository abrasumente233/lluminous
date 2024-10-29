const typography = require('@tailwindcss/typography');
const defaultTheme = require('tailwindcss/defaultTheme')

function scrollbarsPlugin({ addUtilities }) {
	addUtilities({
		'.scrollbar-white': {
			'&::-webkit-scrollbar-track': {
				background: 'white',
			},
			'&::-webkit-scrollbar-thumb': {
				background: 'white',
			},
		},
		'.scrollbar-slim': {
			'&::-webkit-scrollbar': {
				width: '6px',
				height: '6px',
			},
			'&::-webkit-scrollbar-track': {
				background: "theme('colors.gray.200 / 70%')",
				'-webkit-border-radius': '10px',
				'border-radius': '10px',
			},
			'&::-webkit-scrollbar-thumb': {
				background: "theme('colors.gray.400 / 50%')",
				'-webkit-border-radius': '10px',
				'border-radius': '10px',
			},
		},
		'.scrollbar-ultraslim': {
			'&::-webkit-scrollbar': {
				width: '3px',
				height: '3px',
			},
			'&::-webkit-scrollbar-track': {
				background: "theme('colors.gray.200 / 70%')",
				'-webkit-border-radius': '10px',
				'border-radius': '10px',
			},
			'&::-webkit-scrollbar-thumb': {
				background: "theme('colors.gray.400 / 50%')",
				'-webkit-border-radius': '10px',
				'border-radius': '10px',
			},
		},
		'.scrollbar-none': {
			'-ms-overflow-style': 'none',
			'scrollbar-width': 'none',
			'&::-webkit-scrollbar': {
				display: 'none',
			},
		},
		'.scrollbar-default': {
			'-ms-overflow-style': 'auto',
			'scrollbar-width': 'auto',
			'&::-webkit-scrollbar': {
				display: 'block',
			},
		},
	});
}

/** @type {import('tailwindcss').Config}*/
const config = {
	content: ['./src/**/*.{html,js,svelte,ts}'],

	theme: {
		extend: {
      fontFamily: {
        'sans': ['merriweather', ...defaultTheme.fontFamily.sans],
      },
			screens: {
				md: '880px',
				ld: '1215px',
				xl: '1432px',
			},
			transitionTimingFunction: {
				'in-out':
					'linear(0, 0.005, 0.02 2.2%, 0.045, 0.081 4.9%, 0.16 7.3%, 0.465 16.2%, 0.561, 0.642,0.713 25.8%, 0.773, 0.825 32.7%, 0.868 36.5%, 0.905 40.9%, 0.935 45.7%,0.958 51.1%, 0.975 57.4%, 0.986 64.4%, 0.993 73.1%, 0.997 84.1%, 0.999)',
			},
		},
	},

	plugins: [typography, scrollbarsPlugin],
};

module.exports = config;
