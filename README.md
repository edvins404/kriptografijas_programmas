# AES-128 (1 bloks) un CBC failu šifrs (C# programmēšanas valoda)

## Ideja īsumā
Šajā projektā tika uzprogrammēts **AES-128** bloka šifrs (šifrēšana + atšifrēšana) un uz tā bāzes arī **CBC failu šifrs**. 

Projekts ir sadalīts sekojoši:
- `Aes128` klase realizē AES darbību ar **vienu 16 baitu (128 bitu) bloku**.
- CBC režīms (failiem) izmanto `Aes128` kā “melno kasti” katra bloka šifrēšanai/atšifrēšanai.

---

## Funkcionalitāte

### 1) AES-128 vienam blokam
Atbilstoši prasībām programma ļauj:
- izvēlēties darbību: **Encrypt (E)** vai **Decrypt (D)**
- ievadīt **128 bitu atslēgu** kā **32 hex simbolus** (`0-9a-f`)
- ievadīt **128 bitu datu bloku** kā **32 hex simbolus** (vai arī kā tekstu, kuru programma pārvērš 16 baitos)
- iegūt rezultātu atpakaļ **32 hex formā**

Papildus ērtībai konsoles interfeisā ir ieviesta:
- iespēja **ģenerēt atslēgu automātiski** (tikai ērtībai),
- **SelfTest** ar zināmo FIPS-197 testvektoru.

### 2) CBC failu šifrs (AES-CBC)
CBC režīmā tiek šifrēts/atšifrēts fails pa 16 baitu blokiem:
- šifrējot ir vajadzīgs **IV (16 baiti)**,
- atšifrējot **IV tiek ņemts no nošifrētā faila 1. bloka**,
- nošifrētais fails ir **par 1 bloku garāks**, jo sākumā tiek pierakstīts IV.

---

## AES-128 realizācija (FIPS-197 loģika)
AES implementācija balstās uz standarta definīciju (FIPS-197): bloks 128 biti, atslēga 128 biti, **Nr = 10 raundi**.

### Datu reprezentācija (State)
Ievades 16 baiti tiek ielikti **4x4 State** masīvā (kolonnu kārtībā), kā tas ir AES aprakstā.

### Šifrēšanas soļi (katrs raunds)
Šifrēšanā tiek izpildītas klasiskās transformācijas:
1. `SubBytes` (S-box aizvietošana)
2. `ShiftRows`
3. `MixColumns` (izņemot pēdējo raundu)
4. `AddRoundKey` (XOR ar raunda atslēgu)

### Atšifrēšana
Atšifrēšana izmanto inversās operācijas:
- `InvShiftRows`, `InvSubBytes`, `InvMixColumns`, un `AddRoundKey` (XOR ir pats sev inverss).

### Key schedule (raundu atslēgas)
Atslēgu grafiks (KeyExpansion) ģenerē 11 atslēgas (sākotnējā + 10 raundiem), izmantojot:
- `RotWord`, `SubWord` (S-box), un `Rcon` konstantes.

### GF(2^8) reizināšana (MixColumns)
`MixColumns` prasa reizināšanu Galua laukā GF(2^8), tipiski ar `xtime()` pieeju (kreisā nobīde + XOR ar `0x1b`, ja vajag).

---

## CBC režīms (failu šifrēšana)
CBC ideja ir “ieķēdēti bloki”:
- `C0 = IV`
- `Ci = AES_Enc( Pi XOR C{i-1} )`
- atšifrējot: `Pi = AES_Dec(Ci) XOR C{i-1}`

IV pievienošana faila sākumā nozīmē, ka nošifrētais fails kļūst par 16 baitiem garāks.

---

## Konsoles lietošana (UI)
AES “1 bloka” programma strādā interaktīvi ar komandām:
- `E` – šifrēt
- `D` – atšifrēt
- `R` – izmantot pēdējo rezultātu kā nākamo ievadi
- `K` – nomainīt/ģenerēt atslēgu
- `T` – palaist FIPS testu
- `Q` – iziet

Ievades formāti:
- bloks var būt **HEX (32 simboli)** vai **teksts (UTF-8 → 16 baiti, pārējais tiek aizpildīts ar nullēm)**

---

## Testēšana
- Iekļauts **SelfTest** ar zināmo AES-128 testvektoru (Key/Plaintext/Ciphertext) no FIPS-197.

---

## Piezīmes / ierobežojumi
- Atslēgas automātiskā ģenerēšana ir tikai ērtībai; uzdevuma būtība (AES realizācija bez gataviem moduļiem/bibliotēkām) no tā nemainās.
- CBC režīmā vienai atslēgai dažādiem failiem jālieto atšķirīgs IV.
