import mistune # pip install mistune==3.0.0rc4
from mistune.renderers.markdown import MarkdownRenderer
import string
import sys

def convert_urlsafe(title):
    alph = string.ascii_letters + string.digits + '-_'
    title = title.strip()

    new_title = []
    for c in title:
        if c not in alph:
            new_title.append('-')
        else:
            new_title.append(c)

    return ''.join(new_title)


markdown_file = sys.argv[1]
markdown_content = open(markdown_file, 'r').read()

markdown_ast = mistune.create_markdown(renderer=None)
ast_markdown = MarkdownRenderer()

results, state = markdown_ast.parse(markdown_content)

for token in results:
    if token['type'] == 'heading' and token['attrs']['level'] == 2:
        title = token['children'][0]['raw']
        row = f'* [{title}](#{convert_urlsafe(title)})'
        print(row)

new_results = []

for token in results:
    if token['type'] == 'heading' and token['attrs']['level'] == 2:
        title = token['children'][0]['raw']
        a = {'type': 'paragraph', 'children': [{'type': 'inline_html', 'raw': f'<a name="{convert_urlsafe(title)}">'}, {'type': 'inline_html', 'raw': '</a>'}]}
        new_results.append(a)
        new_results.append(token)
    elif token['type'] == 'heading' and token['attrs']['level'] == 1:
        continue
    else:
        new_results.append(token)

print(ast_markdown(new_results, state))