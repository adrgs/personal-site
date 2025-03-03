/* eslint-disable import/no-extraneous-dependencies */
import tailwindcss from 'tailwindcss';
import autoprefixer from 'autoprefixer';
import cssnano from 'cssnano';

const plugins = [tailwindcss, autoprefixer];

if (process.env.NODE_ENV === 'production') {
  plugins.push(
    cssnano({
      preset: [
        'default',
        {
          discardComments: {
            removeAll: true,
          },
        },
      ],
    }),
  );
}

export default {
  plugins,
};
