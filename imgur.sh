#!/bin/bash

# Directory where images will be downloaded
download_dir="./src/assets/images/posts"

# Ensure the download directory exists
mkdir -p "$download_dir"

# Find all Imgur URLs in the ./src directory and process each URL
grep -ERho '(http|https)://i.imgur.com/[^)]+' ./src | sort -u | while read -r url; do
    # Extract the filename from the URL
    filename=$(basename "$url")

    # Download the image to the specified directory
    wget -q -P "$download_dir" "$url"

    # Replace the URL in all files within ./src with the new path
    find ./src -type f -iname '*.md' -exec gsed -i "s|${url}|/assets/images/posts/${filename}|g" {} \;
done

echo "Processing completed."