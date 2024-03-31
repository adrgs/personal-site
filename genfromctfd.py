import json

data = json.load(open('ctfd.json'))

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

s = []

for chall in data['data']:
  title = chall['name']
  points = chall['value']
  solves = chall['solves']
  category = chall['category']
  if category != 'Web':
    continue
  url = title_to_url(title)
  title = f'{title} ({points} pts, {solves} {"solve" if solves == 1 else "solves"}) - {category}'
  s.append(url)

  markdown_table.append(
      mardown_format % (title, url)
  )

  print(myformat % (url, title, ''))
  print()

print('\n'.join(markdown_table))