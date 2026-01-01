# AES-128 un AES-128-CBC (konsoles projekts)

Šajā repozitorijā: konsoles programma ar diviem režīmiem. Viens režīms ir AES-128 šifrēšana/atšifrēšana vienam 16 baitu blokam, un otrs režīms ir failu šifrēšana CBC režīmā (AES-128-CBC).


## Saturs

Galvenie faili projektā:
- `Program.cs` – galvenā izvēlne un režīmu palaišana.
- `AES128.cs` – AES-128 realizācija (Encrypt/Decrypt vienam blokam, key schedule, transformācijas).
- `AES.cs` – konsoles daļa AES-128 režīmam (ievade, komandas, self-test).
- `CBC.cs` – konsoles daļa CBC režīmam (failu šifrēšana/atšifrēšana, IV, padding, self-test).


### 1) AES-128 (viens 16 baitu bloks)

Šifrē vai atšifrē vienu 16 baitu (128 bitu) bloku ar AES-128.

**Ievade**  
- Atslēga: 128 biti (16 baiti) = **32 hex simboli**  
- Dati: 16 baiti, ko var ievadīt:
  - kā **32 hex simbolus**, vai
  - kā tekstu (UTF-8), kuru programma ieliek 16 baitu blokā (ja teksts īsāks, pārējo aizpilda ar `0x00`)

**Izvade**  
- Rezultātu kā 32 hex simbolus (16 baiti)  
- Papildus arī kā tekstu, ērtībai
- 
**Paštests**  
Ir komanda, kas palaiž FIPS-197 testa vektoru (skat. sadaļu “Paštests (FIPS-197)”).

---

### 2) AES-128-CBC (failu šifrēšana)

Šifrē vai atšifrē failu, izmantojot CBC režīmu virs AES-128 bloka šifra. Fails tiek apstrādāts pa 16 baitu blokiem.

**Ievade**  
- Atslēga: 128 biti (16 baiti) = **32 hex simboli** 
- Šifrējot: IV (128 biti = 32 hex simboli) 
- Failu ceļus: ievades fails + izvades fails

**Izvade**  
- Šifrējot: šifrēto failu, kura sākumā ir IV (1. bloks), un pēc tam šifrteksts  
- Atšifrējot: atjaunoto plaintext failu

**Piezīmes**  
- Šifrētais fails ir **par 1 AES bloku (16 baitiem) garāks**, jo pirmais bloks ir IV.  
- Plaintext tiek papildināts ar **PKCS#7 padding**, lai garums dalītos ar 16. Atšifrējot padding tiek noņemts.

---

## Kā izskatās šifrētais fails (CBC formāts)

CBC šifrētais fails ir šāds:

- 1. bloks (16 baiti): **IV**
- pārējie bloki: **CBC šifrteksts**

Tas nozīmē, ka šifrētais fails vienmēr ir par **16 baitiem garāks** nekā plaintext fails.

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

