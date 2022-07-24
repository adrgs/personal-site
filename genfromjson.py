import json
from unicodedata import category

data = json.load(open('cyberedu.json'))

# transform a title into urlsafe title
def title_to_url(title):
    title = title.lower()
    l = []
    for c in title:
        if c.isalpha():
            l.append(c)
        elif c.isnumeric():
            l.append(c)
        else:
            l.append('-')
    return ''.join(l)

myformat = """<a name="%s"></a>
## %s

Description:
```
%s
```"""

mardown_format = """* [%s](#%s)"""


markdown_table = []

s = set()

for card in data:
    title = card['title']
    description = card['description']
    points = card['points']
    difficulty = card['difficulty']
    solves = card['counts']['owned']
    categories = ', '.join([x['name'] for x in card['tags']])
    url = title_to_url(title)
    title = f'{title} ({points} pts, {solves} {"solve" if solves == 1 else "solves"}) - {categories}'

    assert url not in s
    s.add(url)

    markdown_table.append(
        mardown_format % (title, url)
    )

    print(myformat % (url, title, description))
    print()

print('\n'.join(markdown_table))