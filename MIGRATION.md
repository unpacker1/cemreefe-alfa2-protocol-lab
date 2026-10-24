# Private → Public güvenli geliştirme akışı

Public repo sadece **tamamen yeni, temiz test kodları** içindir. Orijinal projelerin mevcut Git geçmişini, branch isimlerini, `git bundle` veya `git subtree` ile aktarma.

**Public (yayımlanabilir):** bağımsız GC paket sayısal boyut testleri, MessagePack v12 örnekleri, hayalî `VID=42` gibi veriler, sentetik hata olayları, bağımsız C++ ABI testleri, güvenlik kontrolü, CI.

**Private (asla yayımlanmaz):** oyun ZIP/APK/AAB, orijinal JS/HTML/GR2/GLB/DDS, native oyun sunucusu ikilileri veya kaynakları (dağıtım izni teyit edilmedikçe), gerçek SQLite/SQL veya DB dump, `*.env`, GitHub PAT/API anahtarı, gerçek kullanıcı adı/şifre, gerçek ağ paket dökümü, orijinal private Git geçmişi, özel kaynak kodu satırları.

Düzeltme yönü: `Public temiz test → gözden geçirme → Private GAME köprüsünde elle uygulama → Termux gerçek GAME testi`. Private kodu otomatik senkronize etmek bu yaklaşımın amacı değildir.

Önemli: **Bir kez Public push yapılmış gizli veriyi daha sonra repoyu Private'a çevirerek güvenli hâle getiremezsin.** History/caches/forklar kalabilir. Bu nedenle yayın öncesi `tools/public_guard.py` zorunludur ve yeni dosya eklemek için scanner allowlist ayrıca değiştirilmelidir.
