# AES-128 un AES-128-CBC (realizēts C# programmēšanas valodā)

Šajā repozitorijā: programma ar diviem režīmiem, kur viens režīms ir AES-128 šifrēšana/atšifrēšana vienam 16 baitu blokam un otrs  ir failu šifrēšana CBC režīmā (AES-128-CBC).

### Kriptogrāfisko bibliotēku izmantošana

AES-128 bloka šifrs un CBC režīms ir realizēti neizmantojot gatavus ietvara šifrēšanas moduļus/bibliotēkas. 

`System.Security.Cryptography` šajā projektā tiek izmantots tikai kriptogrāfiski drošai nejaušu baitu ģenerēšanai atslēgām un inicializācijas vektoram (IV), izmantojot `RandomNumberGenerator.Fill(...)`. 
Šī funkcionalitāte ir paredzēta papildus ērtībai. Atslēgu un IV ir iespējams ievadīt arī manuāli (32 hex simboli), atbilstoši uzdevuma ievades formātam.

## Saturs

Galvenie faili projektā:
- `Program.cs` – galvenā izvēlne un režīmu palaišana.
- `AES128.cs` – AES-128 (core) realizācija (Encrypt/Decrypt vienam blokam, key schedule, transformācijas).
- `AES.cs` – konsoles daļa AES-128 režīmam (ievade, komandas, self-test).
- `CBC.cs` – konsoles daļa CBC režīmam (failu šifrēšana/atšifrēšana, IV, padding, self-test).


### 1) AES-128 (viens 16 baitu bloks)

Šifrē vai atšifrē vienu 16 baitu (128 bitu) bloku ar AES-128.

**Ievade**  
- Atslēga: 128 biti (16 baiti) = **32 hex simboli**  
- Dati: 16 baiti, ko var ievadīt:
  - kā **32 hex simbolus**,
  - kā tekstu (UTF-8), kuru programma ieliek 16 baitu blokā (ja teksts ir īsāks, tad pārējais tiek aizpildīts ar `0x00`)

**Izvade**  
- Rezultātu kā 32 hex simbolus (16 baiti)  
- Papildus klāt kā tekstu, ērtībai

**Paštests**  
Ir komanda, kas palaiž FIPS-197 testa vektoru (skat. sadaļu “Paštests (FIPS-197)”).

---

### 2) AES-128-CBC 

Šifrē vai atšifrē failu, izmantojot CBC režīmu virs AES-128 bloka šifra. Fails tiek apstrādāts pa 16 baitu blokiem.

**Ievade**  
- Atslēga: 128 biti (16 baiti) = **32 hex simboli** 
- Šifrējot: IV (128 biti = 32 hex simboli) 
- Failu ceļus: ievades fails + izvades fails

**Izvade**  
- Šifrējot: šifrēto failu, kura sākumā ir IV (1. bloks), un pēc tam šifrteksts  
- Atšifrējot: atjaunoto plaintext failu

**Piezīmes**  
- Šifrētais fails sākas ar **IV (1 AES bloks = 16 baiti)**.  
- Plaintext tiek papildināts ar **PKCS#7 padding**, lai garums dalītos ar 16. Atšifrējot padding tiek noņemts.  

---

## Šifrētais fails (CBC)

CBC šifrētais fails:

- 1. bloks (16 baiti): **IV**
- pārējie bloki: **CBC šifrteksts**

Tas nozīmē, ka šifrētā faila sākumā ir IV (16 baiti). Papildus tiek lietots PKCS#7 padding, tāpēc šifrētais fails ir par 16 baitiem + padding garumu (1..16 baiti) garāks nekā plaintext.

## Projektējuma apraksts

AES implementācijā tiek ievērota klasiskā AES-128 struktūra (10 raundi). Šifrēšanā ir:
- sākumā `AddRoundKey`,
- tad 9 pilnie raundi ar `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`,
- un pēdējais raunds bez `MixColumns`.

Atšifrēšanā tiek izmantotas inversās transformācijas, un raundu atslēgas tiek pielietotas apgrieztā secībā (sākot ar pēdējā raunda atslēgu).

CBC daļā tiek lietota CBC formula:
- šifrēšana: `C_i = E_K(P_i XOR C_{i-1})`, kur `C_0 = IV`
- atšifrēšana: `P_i = D_K(C_i) XOR C_{i-1}`

Failu apstrāde tiek veikta pa 16 baitu blokiem, un `IV` tiek saglabāts faila sākumā.



## Paštests (FIPS-197)

Programma pārbauda klasisko AES-128 testa vektoru:

- Key: `000102030405060708090a0b0c0d0e0f`  
- Plaintext: `00112233445566778899aabbccddeeff`  
- Ciphertext (jābūt): `69c4e0d86a7b0430d8cdb78070b4c55a`

Ja tas sakrīt, programma izvada, ka tests ir izdevies (`OK`). 

