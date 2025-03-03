import { DateTime } from 'luxon';
import CleanCSS from 'clean-css';
import fs from 'fs';
import htmlmin from 'html-minifier';
import pluginRss from '@11ty/eleventy-plugin-rss';
import { EleventyHtmlBasePlugin } from '@11ty/eleventy';
import pluginSyntaxHighlight from '@11ty/eleventy-plugin-syntaxhighlight';
import ejsPlugin from '@11ty/eleventy-plugin-ejs';
import dateFns from 'date-fns';

// Import our custom EJS engine configurator

export default function (eleventyConfig) {
  // Apply plugins
  eleventyConfig.addPlugin(pluginRss);
  eleventyConfig.addPlugin(EleventyHtmlBasePlugin);
  eleventyConfig.addPlugin(pluginSyntaxHighlight);

  // Configure EJS with the dedicated plugin
  eleventyConfig.addPlugin(ejsPlugin);

  // Make date-fns available in templates
  eleventyConfig.addGlobalData('dateFns', dateFns);

  // Passthrough file copy
  eleventyConfig.addPassthroughCopy({ 'public/assets': 'assets' });
  eleventyConfig.addPassthroughCopy('robots.txt');
  eleventyConfig.addPassthroughCopy('favicon.ico');
  eleventyConfig.addPassthroughCopy('apple-touch-icon.png');
  eleventyConfig.addPassthroughCopy('favicon-32x32.png');
  eleventyConfig.addPassthroughCopy('favicon-16x16.png');
  eleventyConfig.addPassthroughCopy('site.webmanifest');
  eleventyConfig.addPassthroughCopy('netlify.toml');
  eleventyConfig.addPassthroughCopy('admin');

  // Add date filter
  eleventyConfig.addFilter('readableDate', (dateObj) => {
    return DateTime.fromJSDate(dateObj, { zone: 'utc' }).toFormat('dd LLLL yyyy');
  });

  // Date formatting filter
  eleventyConfig.addFilter('htmlDateString', (dateObj) => {
    return DateTime.fromJSDate(dateObj, { zone: 'utc' }).toFormat('yyyy-LL-dd');
  });

  // Add CSS minifier filter
  eleventyConfig.addFilter('cssmin', function (code) {
    return new CleanCSS({}).minify(code).styles;
  });

  // This is necessary for using the Eleventy 3.0 Directory Data Files format
  eleventyConfig.setDataFileBaseName('_data');

  // Minify HTML output
  eleventyConfig.addTransform('htmlmin', function (content, outputPath) {
    if (outputPath && outputPath.endsWith('.html')) {
      return htmlmin.minify(content, {
        useShortDoctype: true,
        removeComments: true,
        collapseWhitespace: true,
        minifyCSS: true,
      });
    }
    return content;
  });

  // Create posts collection
  eleventyConfig.addCollection('posts', function (collectionApi) {
    return collectionApi.getFilteredByGlob('src/posts/**/*.md');
  });

  // Always return all pages, sorted by date
  eleventyConfig.addCollection('all', function (collectionApi) {
    return collectionApi
      .getAll()
      .filter((item) => item.url) // Filter out items without URLs (like robots.txt)
      .sort((a, b) => {
        if (!a.date) return 1;
        if (!b.date) return -1;
        return b.date - a.date;
      });
  });

  // Define layout aliases for consistent referencing
  eleventyConfig.addLayoutAlias('base.ejs', 'layouts/base.ejs');
  eleventyConfig.addLayoutAlias('post.ejs', 'layouts/post.ejs');

  return {
    dir: {
      input: 'src',
      output: '_site',
      includes: '_includes',
      layouts: '_includes',
    },
    // Specify the template engines
    templateFormats: ['md', 'ejs', 'html'],
    markdownTemplateEngine: 'ejs',
    htmlTemplateEngine: 'ejs',
    dataTemplateEngine: 'ejs',
  };
}
