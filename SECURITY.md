# Güvenlik ve veri sınırları

- Bu repo herhangi bir gerçek hesabın şifresini, erişim jetonunu, API anahtarını, özel repo bağlantısını veya orijinal oyun dosyasını içermez.
- Sentetik test fixture dışında network capture, packet dump veya gerçek sağlık kayıtları yayınlanmaz.
- Public Actions workflow'u Private repolara erişmez, `GITHUB_TOKEN` ile Private repository checkout yapmaz; yalnız kendi sentetik testlerini çalıştırır.
- `tools/public_guard.py` izin verilen her dosyanın tam adını listeler; başka bir dosya eklenirse yayını durdurur.
- PR incelemesinden önce `python3 tools/public_guard.py .` çalıştır.
- Gerçek bir güvenlik açığı veya gizli anahtar fark edersen Public issue açmadan önce depoya yazma; yerel olarak kaldır, anahtarı iptal et/döndür ve güvenli bildirim kanalı kullan.
