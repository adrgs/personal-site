table = """
* [Zootopia 1 (50) - Exploit](#zootopia1)
* [Zootopia 2 (50) - Exploit](#zootopia2)
* [Zootopia 3 (75) - Exploit](#zootopia3)
* [Zootopia 4 (75) - Exploit](#zootopia4)
* [Only a Way Out (100) - Exploit](#onlyawayout)
* [Missing Piece (150) - Exploit](#missingpiece)
* [Name Database (200) - Exploit](#namedatabase)
* [Super Jump (125) - Misc](#superjump)
* [Psychological Warfare (100) - Reverse](#psychologicalwarfare)
* [Swim with the Sharks (100) - Reverse](#swimwiththesharks)
* [Magic Library (150) - Reverse](#magiclibrary)
* [Good Looking (100) - Web](#goodlooking)
* [Cashflow (200) - Web](#cashflow)
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