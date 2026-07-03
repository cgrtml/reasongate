# Stakes Demo — "aynı saldırı, tek değişken: kalkan"

Bu demo bir *mekanizma* değil, bir *sonuç* gösterir. Bir banka müşteri-hizmet
ajanı düşünün: elinde gizli müşteri verisi ve iki araç var (`send_email`,
`transfer_funds`). Saldırı kullanıcının isteğinde değil — ajanın **getirdiği
müşteri kaydının içine** gizlenmiş (prod'daki en yaygın dolaylı-enjeksiyon
deseni).

İhlalin kanıtı ajanın *cümlesi* değil, **gerçek bir yan etki**: araçlar
çağrılınca içerik gerçekten diske yazılır (`_sideeffects/`). Böylece "kötü bir
şey söyledi" ile "gerçekten bir ihlal oldu" karışmaz.

## Üç koşu

| # | Kalkan | Kayıt | Sonuç |
|---|--------|-------|-------|
| 1 | **KAPALI** | zehirli | **İHLAL** — müşteri kaydı saldırgana e-postalanır + izinsiz transfer yapılır |
| 2 | **AÇIK** | zehirli | **BLOKLANDI** — *aynı girdi*, tek fark kalkan; ajan/model hiç çağrılmaz, sıfır yan etki |
| 3 | **AÇIK** | temiz | **İZİN** — ajan limit sorusunu normal yanıtlar, yan etki yok |

Koşu **1 ↔ 2** "wow"u verir (tek değişken kalkan). Koşu **3** "bu aptal bir
blocklist değil"in kanıtıdır — meşru trafik engellenmez.

## Çalıştır

```bash
pip install -e .
python -m examples.stakes_demo.run
# renksiz (log/CI): python -m examples.stakes_demo.run --no-color
```

Varsayılan olarak **deterministik mock** model kullanılır (anahtarsız, her koşuda
aynı). Gerçek modele karşı doğrulamak isterseniz:

```bash
export ANTHROPIC_API_KEY=sk-...
python -m examples.stakes_demo.run
```

Mock, naif bir araç-kullanan ajanın bilinen davranışını (bağlamdaki emirlere
uyma) deterministik olarak yeniden üretir; gerçek-API yolu bunun uydurma
olmadığını herkesin doğrulayabilmesi içindir. Her iki durumda da ispat aynı:
ReasonGate zehirli bağlamı **model hiç çağrılmadan** durdurur.

## Kanıt diskte

```bash
cat examples/stakes_demo/_sideeffects/outbox.jsonl   # koşu 1'den sonra: sızan kayıt
cat examples/stakes_demo/_sideeffects/ledger.jsonl   # koşu 1'den sonra: izinsiz transfer
```

Koşu 2 ve 3'ten sonra bu dosyalar **boştur**.

## Regresyon garantisi

Demo bir kerelik gösteri değil: `tests/test_stakes_demo.py` üç şartı da her
commit'te doğrular (OFF ihlal üretir · ON bloklar · ON+temiz izin verir).

```bash
pytest tests/test_stakes_demo.py -v
```

## GIF / asciinema kaydı (vitrin için)

```bash
# asciinema:
asciinema rec stakes.cast -c "python -m examples.stakes_demo.run"
# ya da vhs (README GIF'i icin):  vhs stakes.tape
```
