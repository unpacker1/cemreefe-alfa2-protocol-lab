# Cemreefe ↔ Alfa2 Protocol Lab (PUBLIC, sanitized)

**Temizden yazılmış protokol test laboratuvarı.** Orijinal oyunun istemcisi, sunucusu, motoru, veritabanı, hesapları, derlenmiş APK'si ve oyun modelleri burada **yoktur**.

## Ne işe yarar?

- Metin2-benzeri native GAME'in **şifresi çözülmüş** ikili paket sınırlarını test eder (gerçek DH2/Crypto++ kodu veya oyun ağı yok).
- Belirli GAME `GC` protokol regresyonlarını üretir: GC106 **9 bayt**, GC114 **6 bayt**, GC115 **5 + 78 × kayıt**, GC130 **3 + 24 × kayıt**, GC17 **17 bayt**.
- TCP parçalanması (veri 1 bayt veya rastgele iki parçaya ayrılsa da) ve eksik gövde/yanlış kayıt sayısı testleri yapar.
- Alfa2 v12 `0x00` güvenilir MessagePack ve `0x01` hareket dizisi çerçeve sözleşmesini test eder.
- `Welcome` ardından native oturum koparsa **tek kullanımlık GAME anahtarının** yeniden kullanılamayacağını taklit eder.
- Python + C++ boyut denetimlerini Public GitHub Actions içinde ücretsiz standart runner'da çalıştırabilir.

## Sınırlar

Bu repo **gerçek DB/AUTH/GAME sunucusunu başlatmaz**. Oyun paketi, sıfırdan portlanmış oyun motoru, gerçek mob AI, gerçek saldırı, skill, eşya ve NPC mağazası bu depoda **yer almaz**. Buradaki paket boyutları bir kaynak sürümüne göre hazırlanmış regresyon sözleşmeleridir; gerçek fork farklı olabilir. Kendi orijinal dosyalarının doğrulamasını ayrı **Private** ortamda yap.

## Termux / Linux yerel test

```bash
python3 -m pip install -e .
python3 tools/public_guard.py .
python3 -m unittest discover -s tests -v
```

## Gerçek oturum hatasını güvenli biçimde sınıflandırma

Bu araç yalnız **yerel** GAME köprüsünün `/api/health` çıktısını alır,
içinden izin verilen tanı alanlarını seçer ve diğer her şeyi atar.
**Ham JSON, paket dökümü, token, kullanıcı adı veya özel dosya yükleme.**

Termux'ta Public repoyu güncelledikten sonra:

```bash
cd ~/cemreefe_alfa2_public_lab
git pull --ff-only

python3 - <<'PY'
import json, urllib.request
from protocol_lab.triage import build_report

health=json.load(urllib.request.urlopen(
    "http://127.0.0.1:8766/api/health",timeout=5))
print(json.dumps(build_report(health),indent=2,ensure_ascii=False))
PY
```

Sadece ekranda çıkan **safeSnapshot + classification** sonucunu
incele. Ham API cevabını GitHub'a **commit etme**. Bu modül gerçek
native sokete bağlanmaz, şifre çözmez ve oyun hesabını değiştirmez.

### GAME soketi EOF/oyundan atma tanısı (yalnız cihazda)

Geliştirme laboratuvarı **DB/AUTH/GAME başlatmaz**. Orijinal
Private GAME ve Alfa2 web sunucusu açıkken, ikinci Termux oturumunda:

```bash
cd ~/cemreefe_alfa2_public_lab
git pull --ff-only

python3 -m protocol_lab.game_exit \
  --runtime "$HOME/CEMREEFE_NATIVE_STANDALONE/runtime"
```

İki ayrı sonuca bak:

- `game_session_eof_listener_still_running`: GAME portu hâlâ açık;
  tek bir karakter oturumu kapandı, **sebebi henüz kesin değil**.
- `game_listener_stopped_after_eof`: GAME portu kapalı;
  servis durmuş veya çökmüş olabilir.

Yeni özellikle `game_ping_no_pong`, `game_pong_received`,
`game_sequence_mismatch`, `game_duplicate_login`,
`game_handshake_rejected` ve `game_session_socket_closed` sayaçlarına
bakılır. İncelenen açık kaynak sunucunun varsayılan PING süresi
60 saniyedir; ancak telefonundaki GAME yapılandırması farklı olabilir.
Sıfır değerleri yalnız taranan **log pencerelerinde** eşleşme olmadığını
gösterir, PING sorunu olmadığını kesinleştirmez.

`localServerLogs.recentLogCategoryCounts` yalnız son 64 KB logdaki
hata anahtar sözcüklerinin **adetlerini** gösterir. Ham satırlar,
karakter ismi, şifre, IP, token ve paket verileri hiçbir şekilde
çıktıya yazılmaz. Bu sayılar tek başına sunucunun gerçekten oyuncuyu
attığını kanıtlamaz; daha ileri kaynak incelemesi Private yapılmalıdır.

### 60 saniyelik native GAME PING / HANDSHAKE kontrolü

Orijinal GAME kaynak kodunda sunucu istemciye periyodik **GC 44 PING**
ve **GC 255 HANDSHAKE** gönderebilir; **GC 252 TIME_SYNC**
onayını da işler. Bu paketler orijinal metin2 istemcisinde karşılanır.
Public laboratuvarda çerçeve boyutu testleri eklenmiştir (1, 13, 1 bayt).
Cevapların GAME tarafında doğru kabul edildiği ayrıca test edilmelidir.

Yerel native kaynak kodunda canlı GAME dalı bunları tanıyor mu?

```bash
cd ~/cemreefe_alfa2_public_lab
git pull --ff-only
python3 -m protocol_lab.source_audit \
  --native-root "$HOME/CEMREEFE_WEB_V1"
python3 -m protocol_lab.game_exit \
  --runtime "$HOME/CEMREEFE_NATIVE_STANDALONE/runtime"
```

`gameHandshakeGc255HandlerPresent=false`: canlı native okuyucuda
bu kontrol mesajı için işleyici tespit edilemedi. Bu **kod kapsamı**
eksikliğidir; bağlantının neden koptuğunu tek başına kanıtlamaz.

`localServerLogs.recentLogCategoryCounts.game_ping_no_pong` ve
`game_sequence_mismatch` sunucu kaynaklarında gerçek olarak kullanılan
iki mesaj biçimidir. Tespit edilen **sayılar eski loglardan da gelebilir**;
gerçek neden için ilgili oturum sırasında artışı izlenmelidir.

Bu denetim hiçbir özel kaynak içeriğini veya sunucu log satırını dışarıya
yazmaz; kaynakları **değiştirmez** ve native binary'yi yeniden derlemez.

C++ test (g++ varsa):

```bash
g++ -std=c++17 -Wall -Wextra -Werror -pedantic cpp/test_frame_contract.cpp -o /tmp/protocol_contract && /tmp/protocol_contract
```

GitHub Actions: `.github/workflows/protocol-ci.yml` — yalnız sentetik testler ve `contents: read` izni.

## Private ↔ Public iş akışı

1. Yeni GAME hatasını **Private cihazda** kaydet; hesap/token/paket verilerini yayımlama.
2. Sadece **sayısal hata türü** ve **yapay baytlarla** tekrar üretilebilir regression testi yaz.
3. Public PR/commit + Actions yeşil ise ilgili codec/test düzeltmesini dikkatlice Private koda **elle seçerek** aktar.
4. Orijinal native GAME/Alfa2 ortamında yeniden derle ve telefon testini yap.
5. Public depoya asla Private repodan `git push --mirror`, fork/transfer, `cp -a`, Git geçmişi veya orijinal ZIP/APK/SQL/GLB taşıma.

Bkz. [MIGRATION.md](MIGRATION.md), [SECURITY.md](SECURITY.md), [STATUS.md](STATUS.md).
