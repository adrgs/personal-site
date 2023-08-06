---
title: 'Delete highlight cover IDOR bug in Instagram'
description: $3,000 bug found for Meta Bug Bounty Conference 2023
date: 2023-08-05T00:00:00Z
---

**Description:**

There was a missing permission check when deleting highlights via the `/async/wbloks/fetch/?appid=com.instagram.privacy.activity_center.highlight_delete&type=action&__bkv=c74d64ab71b2a21df8ce5c1e4147b1401fbc630d5829338fd53180777d4cfcda` API which results in the highlight cover being deleted for other users if the cover is a uploaded image (so not a story).

The API can be accessed via the web interface at [https://www.instagram.com/your_activity/photos_and_videos/highlights](https://www.instagram.com/your_activity/photos_and_videos/highlights) by selecting the highlight then clicking Delete.

For the image to be deleted the attacker must be able to view the highlight, so either the target is a public account or target is private + attacker follows target.

The cover images that I've tested against were uploaded via the Instagram mobile app.

**Impact:**

Deletion of cover image for highlights. The new cover image will default to the first story in the highlight.

**Repro Steps:**
Users - UserA, UserB

**Environment:** UserA with HighlightA and HighlightCoverA, UserB with HighlightB, UserB can view HighlightA

1. UserB gets HighlightA's id
2. UserB calls delete on HighlightB via the previously specified endpoint
3. UserB modifies items_for_action in the &params POST parameter so that it now contains HighlightA's id
4. HighlightCoverA gets deleted, cover of HighlightA defaults to first story

Here's an example POST request:
```
POST /async/wbloks/fetch/?appid=com.instagram.privacy.activity_center.highlight_delete&type=action&__bkv=c74d64ab71b2a21df8ce5c1e4147b1401fbc630d5829338fd53180777d4cfcda HTTP/2
Host: www.instagram.com

some_params=some_data&params={... ,"items_for_action":"<highlight id>","number_of_items":1}
```

**Video Proof of Concept:**

<div style="align:center">
<iframe width="640" height="360" src="https://www.youtube.com/embed/_zkxePwnf9A"></iframe>
</div>

**Timeline:**

- 10/06/2023 - Reported vulnerability
- 11/06/2023 - Triaged by Meta
- 13/06/2023 - Vulnerability fixed
- 28/06/2023 - $500 bounty awarded
- 28/07/2023 - Impact was reconsidered and extra $2500 were awarded (+ 1.1x Gold league multiplier)