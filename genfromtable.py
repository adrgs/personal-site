table = """
* [megavault](#megavault)
* [Lockpick 1](#Lockpick-1)
* [twin](#twin)
* [bmpass](#bmpass)
* [breaking news](#breaking-news)
* [collector](#collector)
* [noble collector](#noble-collector)
* [Read the Rules](#Read-the-Rules)
* [babyrand](#babyrand)
* [randrevenge](#randrevenge)
* [randrevengerevenge](#randrevengerevenge)
* [the sound of the flags](#the-sound-of-the-flags)
* [spygame](#spygame)
* [Rain checks](#Rain-checks)
* [pythopia](#pythopia)
* [wheel](#wheel)
* [LovR](#LovR)
* [reguest](#reguest)
* [zpr](#zpr)
"""

table = [x for x in table.split('\n') if len(x)>5]

pattern = """<a name="%s"></a>
## %s"""

for t in table:
    p1 = t.split('[')[1].split(']')[0]
    p2 = t.split('(#')[1].split(')')[0]
    x = pattern %(p2, p1)

    print(x)
    print()