import glob from 'glob';
import path from 'path';
import { fileURLToPath } from 'url';
import CopyWebpackPlugin from 'copy-webpack-plugin';
import HtmlWebpackPlugin from 'html-webpack-plugin';
import MiniCssExtractPlugin from 'mini-css-extract-plugin';

// eslint-disable-next-line no-underscore-dangle
const __filename = fileURLToPath(import.meta.url);
// eslint-disable-next-line no-underscore-dangle
const __dirname = path.dirname(__filename);

// Define entry points
const entry = {
  main: path.resolve(__dirname, 'src/assets/styles/tailwind-compiled.css'),
};

// Add syntax highlighting CSS
entry.prism = path.resolve(__dirname, 'src/assets/styles/prism-atom-dark.css');

// Process images separately
const imageEntries = glob.sync(
  path.resolve(__dirname, 'src/assets/images/posts/*.{png,gif,jpg,jpeg}'),
);

// Define CSS output filename
let cssFileName = 'styles/[name].css';
if (process.env.NODE_ENV === 'production') {
  cssFileName = 'styles/[name].[contenthash].css';
}

export default {
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',
  devtool: 'source-map',
  stats: {
    colors: true,
    preset: 'minimal',
  },
  entry,
  output: {
    path: path.resolve(__dirname, '_site/assets'),
    publicPath: '/assets/',
    clean: false,
  },
  plugins: [
    new CopyWebpackPlugin({
      patterns: [
        { from: path.resolve(__dirname, 'public'), to: path.resolve(__dirname, '_site') },
        ...imageEntries.map((imagePath) => ({
          from: imagePath,
          to: path.resolve(__dirname, '_site/assets/images/posts/[name].[ext]'),
          toType: 'template',
        })),
      ],
    }),
    new MiniCssExtractPlugin({
      filename: cssFileName,
    }),
    new HtmlWebpackPlugin({
      template: path.resolve(__dirname, 'webpack.html'),
      filename: path.resolve(__dirname, 'src/_includes/layouts/webpack.ejs'),
      inject: false,
    }),
  ],
  module: {
    rules: [
      {
        test: /\.css$/,
        use: [
          MiniCssExtractPlugin.loader,
          {
            loader: 'css-loader',
            options: {
              importLoaders: 1,
              // Use url: false to prevent css-loader from processing url() functions
              url: false,
            },
          },
          {
            loader: 'postcss-loader',
            options: {
              postcssOptions: {
                config: path.resolve(__dirname, 'postcss.config.js'),
              },
            },
          },
        ],
      },
      {
        test: /\.(gif|png|jpg|jpeg)$/i,
        type: 'asset/resource',
        generator: {
          filename: 'images/posts/[name][ext]',
        },
      },
    ],
  },
};
