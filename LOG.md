# PSWAP Simple — Testnet Run Log

Successful run of `pswap_simple` on Miden testnet (v0.13, no fees).

```
============================================================
PSWAP SIMPLE PARTIAL FILL (NO FEES, v0.13)
============================================================

Store: "/var/folders/xw/4clfg4sx16bbdx6t823p0ctr0000gn/T/pswap_simple_1771427729847/store.sqlite3"
Keystore: "/var/folders/xw/4clfg4sx16bbdx6t823p0ctr0000gn/T/pswap_simple_1771427729847/keystore"

--- Initial Sync ---
Block: 253851

============================================================
PHASE 1: CREATE FAUCETS
============================================================

=== GOLD FAUCET ===
  GOLD ID:     0xe1efd77c2c406e20664b9c80d95b6f
  GOLD prefix:  16280468106285968928 (0xe1efd77c2c406e20)
  GOLD suffix:  7371157292338343680 (0x664b9c80d95b6f00)

=== SILVER FAUCET ===
  SILVER ID:     0x1f2bf2089457ce2063004445fffcfb
  SILVER prefix:  2246154957836766752 (0x1f2bf2089457ce20)
  SILVER suffix:  7133776877193067264 (0x63004445fffcfb00)

============================================================
PHASE 2: CREATE WALLETS
============================================================

=== MAKER ===
  Maker ID:     0x854d7f2892037a1078a9a575d2bc4d
  Maker prefix:  9605473392476256784 (0x854d7f2892037a10)
  Maker suffix:  8694662481080765696 (0x78a9a575d2bc4d00)

=== TAKER ===
  Taker ID:     0xa13a0f543cf4ab102010e93b62fd3f
  Taker prefix:  11617615043229952784 (0xa13a0f543cf4ab10)
  Taker suffix:  2310603050114170624 (0x2010e93b62fd3f00)

============================================================
PHASE 3: MINT TOKENS
============================================================

Minting 100000 GOLD to Maker...
Minting 25000 SILVER to Taker...

Waiting for mints to commit (30s)...

--- Consuming Minted Notes ---
  Maker consumed mint note(s)
  Taker consumed mint note(s)

Waiting for consumption to commit (30s)...

============================================================
PHASE 4: CREATE PSWAP NOTE
============================================================

Offer: 100000 GOLD for 100000 SILVER (1:1 ratio)
SDK P2ID root words: [13362761878458161062 15090726097241769395 444910447169617901 3558201871398422326]
one or more warnings were emitted

=== NOTE INPUTS (14) ===
  input[ 0]:               100000 (0x00000000000186a0)
  input[ 1]:                    0 (0x0000000000000000)
  input[ 2]:  7133776877193067264 (0x63004445fffcfb00)
  input[ 3]:  2246154957836766752 (0x1f2bf2089457ce20)
  input[ 4]:           1321591071 (0x000000004ec5e11f)
  input[ 5]:            559087616 (0x0000000021530000)
  input[ 6]:                    0 (0x0000000000000000)
  input[ 7]:                    0 (0x0000000000000000)
  input[ 8]:                    0 (0x0000000000000000)
  input[ 9]:                    0 (0x0000000000000000)
  input[10]:                    0 (0x0000000000000000)
  input[11]:                    0 (0x0000000000000000)
  input[12]:  9605473392476256784 (0x854d7f2892037a10)
  input[13]:  8694662481080765696 (0x78a9a575d2bc4d00)

=== PSWAP NOTE CREATED ===
  Note ID: 0x5862be60ba1936aa2468ea82eb9eba605eabe4a47fd2897c53634a2b2409fdfd
  Tag: NoteTag(1321591071)
  SWAPP transaction submitted

--- Waiting for SWAPP note to be consumable ---
  Polling 1/24...
  Note consumable after 2 attempts

============================================================
PHASE 5: TAKER FILLS 25%
============================================================
  Block: 253962

Fill calculation:
  Fill amount:        25000 SILVER (taker sends)
  Maker receives:     25000 SILVER
  Taker receives:     25000 GOLD
  Leftover offered:   75000 GOLD (in new SWAPP)
  Leftover requested: 75000 SILVER (in new SWAPP)

Expected Maker P2ID Note ID: 0xe71bcb7424c5a100393348589df9e81651a917e3b588d27036fb67cc30c91f72

=== NOTE INPUTS (14) ===
  input[ 0]:                75000 (0x00000000000124f8)
  input[ 1]:                    0 (0x0000000000000000)
  input[ 2]:  7133776877193067264 (0x63004445fffcfb00)
  input[ 3]:  2246154957836766752 (0x1f2bf2089457ce20)
  input[ 4]:           1321591071 (0x000000004ec5e11f)
  input[ 5]:            559087616 (0x0000000021530000)
  input[ 6]:                    1 (0x0000000000000001)
  input[ 7]:                    2 (0x0000000000000002)
  input[ 8]:                    1 (0x0000000000000001)
  input[ 9]:                    0 (0x0000000000000000)
  input[10]:                    3 (0x0000000000000003)
  input[11]:                    4 (0x0000000000000004)
  input[12]:  9605473392476256784 (0x854d7f2892037a10)
  input[13]:  8694662481080765696 (0x78a9a575d2bc4d00)
Expected Leftover Note ID: 0xd178332baf8c871f79b9c29a4064959ada71e4d31a9911465ec47569c21cf1fc

--- Submitting Fill Transaction ---
  Transaction ID: 0xd8ba239bd9d43b4572083477f3a1ff0f1f8d27950e3cd107fa03b8693f820680

============================================================
MIDENSCAN LINKS
============================================================
  Maker:    https://testnet.midenscan.com/account/0x854d7f2892037a1078a9a575d2bc4d
  Taker:    https://testnet.midenscan.com/account/0xa13a0f543cf4ab102010e93b62fd3f
  P2ID:     https://testnet.midenscan.com/note/0xe71bcb7424c5a100393348589df9e81651a917e3b588d27036fb67cc30c91f72
  Leftover: https://testnet.midenscan.com/note/0xd178332baf8c871f79b9c29a4064959ada71e4d31a9911465ec47569c21cf1fc

Waiting for fill to commit (45s)...
  Sync OK, block: 253995

============================================================
PHASE 6: MAKER CONSUMES P2ID
============================================================
  P2ID consumable after 1 attempts

Waiting for P2ID consumption (30s)...

============================================================
FINAL BALANCES
============================================================
  Maker:  GOLD=0, SILVER=25000 (expected 0, 25000)
  Taker:  GOLD=25000, SILVER=0 (expected 25000, 0)
  Leftover SWAPP: 75000 GOLD (note 0xd178332baf8c871f79b9c29a4064959ada71e4d31a9911465ec47569c21cf1fc)

Done.
```
