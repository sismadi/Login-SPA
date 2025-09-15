# SPA Login GitHub + Cloudflare Worker

Worker ini menyediakan **SPA login sederhana via GitHub OAuth**.  
Client secret **tidak pernah** berada di browser—disimpan di Worker, sedangkan sesi user disimpan di **KV (namespace `SESSIONS`)**.

---

## Yang perlu kamu lakukan (cepat & pasti)

### 1) Isi _secrets_ di Worker (Dashboard)
- Buka **Workers & Pages → pilih worker `spa` → Settings → Variables → Add**
- **Add secret → `GITHUB_CLIENT_ID`** → isi Client ID dari GitHub OAuth App  
- **Add secret → `GITHUB_CLIENT_SECRET`** → isi Client Secret  
- (Opsional) `APP_URL` **tidak wajib** karena kode sudah memakai `url.origin`
- **Save** lalu **Deploy** (kanan atas). Pastikan environment yang aktif **Production** (sesuai URL yang kamu akses)

### 2) Pastikan OAuth App di GitHub benar
- **Homepage URL**: `https://spa.wawan.workers.dev`  
- **Authorization callback URL**: `https://spa.wawan.workers.dev/auth/callback`  
- **Save / Update application**


