---
title: 'Hello world'
description: Lorem ipsum dolor sit amet, consectetur adipiscing elit.
date: 2022-02-20T00:00:00Z
---

# Hello world!

```py

from pwn import *

r = remote('192.168.1.1', 4444)
r.sendline(b'test')

# Get the flag!!

```