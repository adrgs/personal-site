// Set default layout for Eleventy 3.0
// https://github.com/11ty/eleventy/issues/380#issuecomment-568033456

export default function (data) {
  // Don't apply a layout to these specific files
  if (
    data.page
    && (data.page.inputPath.endsWith('robots.ejs')
      || data.page.inputPath.endsWith('sitemap.ejs')
      || data.page.url === '/robots.txt'
      || data.page.url === '/sitemap.xml')
  ) {
    return null;
  }

  // Default layout for all other pages
  return 'base.ejs';
}
