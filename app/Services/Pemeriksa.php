<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

// Mengambil ciri dari internet: DNS, RDAP, sertifikat SSL, unduhan HTML + redirect, peringkat Tranco.
// Hasil: 'nilai' = fitur => sah|curiga|phishing, 'gagal' = fitur => alasan. Fitur yang gagal diambil tidak
// masuk 'nilai', jadi dropdown manual tetap dipakai untuk melengkapinya.
// Server membuka alamat dari pengguna, jadi alamat internal ditolak (SSRF) dan tiap hop redirect divalidasi ulang.
class Pemeriksa
{
    public static function periksa(string $url): array
    {
        $url = trim($url);
        if (! preg_match('~^[a-z][a-z0-9+.-]*://~i', $url)) {
            $url = 'http://'.$url;
        }
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));
        if (! self::hostSah($host)) {
            return ['nilai' => [], 'gagal' => [], 'domain' => null];
        }

        $nilai = $gagal = [];
        $terdaftar = null; // dari RDAP: true = terdaftar, false = RDAP menjawab 404, null = tidak diketahui
        $htmlFitur = ['Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'Favicon', 'Submitting_to_email', 'on_mouseover', 'RightClick', 'Iframe'];
        // Urutan penting: halaman() boleh menimpa SSLfinal_State (halaman akhir masih http://).
        // Elemen ke-3 true = butuh alamat IP situs, jadi dilewati bila DNS sudah memastikan domainnya tidak ada.
        foreach ([
            [['DNSRecord'], fn () => ['DNSRecord' => self::dns($host)], false],
            [['Domain_registeration_length', 'age_of_domain'], fn () => self::rdap($host), false],
            [['SSLfinal_State'], fn () => ['SSLfinal_State' => self::ssl($host)], true],
            [['web_traffic'], fn () => ['web_traffic' => self::tranco($host)], false],
            [['Redirect', ...$htmlFitur], fn () => self::halaman($url, $htmlFitur), true],
        ] as [$fitur, $ambil, $butuhIp]) {
            if ($butuhIp && ($nilai['DNSRecord'] ?? '') === 'phishing') {
                foreach ($fitur as $k) {
                    $gagal[$k] = 'domain tidak ditemukan di DNS';
                }

                continue;
            }
            try {
                foreach ($ambil() as $k => $v) { // nilai berawalan "!" = alasan gagal untuk fitur itu saja
                    if (str_starts_with($v, '!')) {
                        $gagal[$k] = substr($v, 1);
                    } else {
                        $nilai[$k] = $v;
                    }
                }
                if ($fitur[0] === 'Domain_registeration_length') {
                    $terdaftar = true;
                }
            } catch (\Throwable $e) {
                if ($fitur[0] === 'Domain_registeration_length' && $e->getCode() === 404) {
                    $terdaftar = false;
                }
                foreach ($fitur as $k) {
                    $gagal[$k] = Str::limit(Str::before($e->getMessage(), ' (see'), 100);
                }
            }
        }

        // Domain "ada" = punya catatan DNS. Tanpa DNS tetapi terdaftar di RDAP berarti domain nonaktif/parkir.
        $dns = $nilai['DNSRecord'] ?? null;

        return [
            'nilai' => $nilai,
            'gagal' => array_diff_key($gagal, $nilai),
            'domain' => $dns === null ? null : ['ada' => $dns === 'sah', 'terdaftar' => $terdaftar],
        ];
    }

    // Nama host aman untuk dipakai di jaringan: hanya huruf/angka/titik/strip, dan bukan IPv4 gaya lain
    // (2130706433, 0x7f.1) yang bisa ditafsirkan berbeda oleh curl dan oleh resolver.
    private static function hostSah(string $host): bool
    {
        return preg_match('/^[a-z0-9.-]+$/', $host)
            && (filter_var($host, FILTER_VALIDATE_IP) || ! preg_match('/(^|\.)(0x[0-9a-f]*|\d+)$/', $host));
    }

    private static function bukanIp(string $host): void
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            throw new \RuntimeException('URL berupa alamat IP, bukan nama domain');
        }
    }

    // Domain terdaftar tanpa daftar public suffix: dua label terakhir, tiga bila bentuknya xxx.co.id / xxx.com.br.
    // ponytail: salah untuk suffix ganda yang jarang (mis. abc.xyz.de), pakai daftar public suffix bila perlu.
    private static function dasar(string $host): string
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }
        $p = explode('.', preg_replace('/^www\./', '', $host));
        $n = count($p);

        return implode('.', array_slice($p, $n > 2 && strlen($p[$n - 1]) == 2 && strlen($p[$n - 2]) <= 3 ? -3 : -2));
    }

    // IPv4 publik pertama dari host. Dipakai untuk menyambung (dipaku lewat CURLOPT_RESOLVE), sehingga
    // DNS rebinding tidak bisa membelokkan sambungan ke jaringan internal.
    // ponytail: hanya IPv4, situs khusus IPv6 jatuh ke dropdown manual.
    private static function ipPublik(string $host): string
    {
        foreach (gethostbynamel($host) ?: [] as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
        throw new \RuntimeException('alamat tidak ditemukan atau menuju jaringan internal');
    }

    private static function dns(string $host): string
    {
        self::bukanIp($host);
        if (gethostbynamel($host) || @dns_get_record($host, DNS_AAAA)) {
            return 'sah';
        }
        if (! gethostbynamel('example.com')) { // pembanding: kalau ini juga gagal, resolver server yang bermasalah
            throw new \RuntimeException('resolver DNS di server tidak bisa dipakai');
        }

        return 'phishing';
    }

    private static function rdap(string $host): array
    {
        self::bukanIp($host);
        $tld = Str::afterLast($host, '.');
        $layanan = Cache::store('file')->remember('rdap-bootstrap', 86400, fn () => Http::timeout(6)->get('https://data.iana.org/rdap/dns.json')->throw()->json('services'));
        $dasar = null;
        foreach ($layanan as [$tlds, $urls]) {
            if (in_array($tld, $tlds, true)) {
                $dasar = collect($urls)->first(fn ($u) => str_starts_with($u, 'https://'));
                break;
            }
        }
        if (! $dasar) {
            throw new \RuntimeException(".$tld belum punya server RDAP");
        }
        $r = Http::timeout(6)->acceptJson()->get(rtrim($dasar, '/').'/domain/'.self::dasar($host));
        if (! $r->ok()) {
            throw new \RuntimeException($r->status() == 404 ? 'domain tidak ditemukan di RDAP' : 'RDAP membalas HTTP '.$r->status(), $r->status() == 404 ? 404 : 0);
        }
        $e = collect($r->json('events', []))->pluck('eventDate', 'eventAction');
        $daftar = strtotime($e['registration'] ?? '');
        $habis = strtotime($e['expiration'] ?? '');

        return [
            'Domain_registeration_length' => $habis ? ($habis - time() > 365 * 86400 ? 'sah' : 'phishing') : '!RDAP tidak memuat tanggal kedaluwarsa',
            'age_of_domain' => $daftar ? (time() - $daftar >= 183 * 86400 ? 'sah' : 'phishing') : '!RDAP tidak memuat tanggal pembuatan',
        ];
    }

    // sah = rantai sertifikat tepercaya + nama cocok + belum kedaluwarsa; curiga = penerbit tidak dikenal (mis. self-signed);
    // phishing = port 443 tertutup, kedaluwarsa, atau nama tidak cocok.
    // ponytail: syarat "umur sertifikat 1 tahun" dari dataset dibuang, sertifikat sekarang berumur 90-200 hari sehingga
    // hampir semua situs sah akan jatuh ke curiga. Jika semua situs jadi curiga, openssl.cafile di php.ini belum diatur.
    private static function ssl(string $host): string
    {
        $ip = self::ipPublik($host);
        $no = 0;
        $buka = function (bool $cek) use ($host, $ip, &$no) {
            $ctx = stream_context_create(['ssl' => [
                'verify_peer' => $cek, 'verify_peer_name' => $cek, 'peer_name' => $host,
                'SNI_server_name' => $host, 'capture_peer_cert' => true,
            ]]);
            $s = @stream_socket_client("ssl://$ip:443", $no, $pesan, 5, STREAM_CLIENT_CONNECT, $ctx);
            if (! $s) {
                return null;
            }
            $c = stream_context_get_params($s)['options']['ssl']['peer_certificate'] ?? null;
            fclose($s);

            return $c ? openssl_x509_parse($c) : null;
        };

        if ($buka(true)) {
            return 'sah';
        }
        if ($c = $buka(false)) {
            return $c['validTo_time_t'] < time() || ! self::namaCocok($c, $host) ? 'phishing' : 'curiga';
        }
        if (in_array($no, [111, 61, 10061], true)) { // ECONNREFUSED (Linux, macOS, Windows)
            return 'phishing';
        }
        throw new \RuntimeException('tidak bisa terhubung ke port 443');
    }

    private static function namaCocok(array $c, string $host): bool
    {
        preg_match_all('/(?:DNS|IP Address):([^,\s]+)/', $c['extensions']['subjectAltName'] ?? '', $m);
        foreach ($m[1] ?: [$c['subject']['CN'] ?? ''] as $n) {
            if (preg_match('/^'.str_replace('\*', '[^.]+', preg_quote(strtolower($n), '/')).'$/', $host)) {
                return true;
            }
        }

        return false;
    }

    // sah = peringkat 1-100.000, curiga = di bawahnya, phishing = tidak masuk daftar.
    private static function tranco(string $host): string
    {
        self::bukanIp($host);
        $r = Http::timeout(6)->acceptJson()->get('https://tranco-list.eu/api/ranks/domain/'.rawurlencode(self::dasar($host)));
        if (! $r->ok() || ! is_array($r->json('ranks'))) {
            throw new \RuntimeException('Tranco membalas HTTP '.$r->status());
        }
        $rank = collect($r->json('ranks'))->sortByDesc('date')->first()['rank'] ?? null;

        return $rank === null ? 'phishing' : ($rank <= 100000 ? 'sah' : 'curiga');
    }

    private static function halaman(string $url, array $htmlFitur): array
    {
        [$hop, $akhir, $isi, $status] = self::unduh($url);
        $hasil = ['Redirect' => $hop <= 1 ? 'sah' : ($hop <= 3 ? 'curiga' : 'phishing')];
        if (str_starts_with($akhir, 'http://')) {
            $hasil['SSLfinal_State'] = 'phishing'; // halaman akhirnya tetap dilayani tanpa HTTPS
        }
        if ($isi === null) {
            return $hasil + array_fill_keys($htmlFitur, "!halaman tidak terbaca (HTTP $status atau bukan HTML)");
        }

        return $hasil + self::isi($isi, strtolower((string) parse_url($akhir, PHP_URL_HOST)));
    }

    // Ikuti redirect satu per satu (maks 5; 4 saja sudah masuk phishing). Tiap hop divalidasi dan dipaku ke IP publik.
    // ponytail: batas ukuran hanya header Content-Length + timeout 6 detik; respons tanpa Content-Length tetap terunduh penuh.
    private static function unduh(string $url): array
    {
        for ($hop = 0; $hop <= 5; $hop++) {
            $p = parse_url($url);
            $host = strtolower($p['host'] ?? '');
            $skema = strtolower($p['scheme'] ?? '');
            if (! in_array($skema, ['http', 'https'], true) || ! self::hostSah($host)) {
                throw new \RuntimeException('alamat tujuan tidak bisa diperiksa');
            }
            $port = $p['port'] ?? ($skema === 'https' ? 443 : 80);
            $r = Http::withoutRedirecting()->withoutVerifying()->timeout(6)->connectTimeout(3)
                ->withHeaders(['User-Agent' => 'Mozilla/5.0 (compatible; PemeriksaPhishing/1.0)'])
                ->withOptions([
                    'curl' => [CURLOPT_RESOLVE => ["$host:$port:".self::ipPublik($host)]],
                    'on_headers' => function ($resp) { // Guzzle melarang CURLOPT_MAXFILESIZE, jadi ukuran dicek dari header
                        if ((int) $resp->getHeaderLine('Content-Length') > 3000000) {
                            throw new \RuntimeException('halaman terlalu besar');
                        }
                    },
                ])
                ->get($url);
            $lokasi = $r->header('Location');
            if ($r->status() < 300 || $r->status() >= 400 || $lokasi === '') {
                break;
            }
            $url = self::gabung($url, $lokasi);
        }
        $html = $r->successful() && str_contains(strtolower($r->header('Content-Type')), 'html') ? substr($r->body(), 0, 2000000) : null;

        return [$hop, $url, $html, $r->status()];
    }

    private static function gabung(string $dasar, string $lokasi): string
    {
        if (preg_match('~^https?://~i', $lokasi)) {
            return $lokasi;
        }
        $p = parse_url($dasar);
        if (str_starts_with($lokasi, '//')) {
            return $p['scheme'].':'.$lokasi;
        }
        $asal = $p['scheme'].'://'.$p['host'].(isset($p['port']) ? ':'.$p['port'] : '');

        return str_starts_with($lokasi, '/')
            ? $asal.$lokasi
            : $asal.'/'.ltrim(preg_replace('~[^/]*$~', '', $p['path'] ?? '/'), '/').$lokasi;
    }

    // Host tujuan sebuah tautan. Tautan relatif dan skema non-http (data:, javascript:) dianggap milik halaman sendiri.
    private static function hostRef(string $ref, string $host): string
    {
        $ref = trim($ref);
        if (str_starts_with($ref, '//')) {
            $ref = 'http:'.$ref;
        }

        return preg_match('~^https?://~i', $ref) ? strtolower((string) parse_url($ref, PHP_URL_HOST)) : $host;
    }

    public static function isi(string $html, string $host): array
    {
        libxml_use_internal_errors(true);
        $dom = new \DOMDocument;
        $dom->loadHTML('<?xml encoding="utf-8"?>'.$html, LIBXML_NOWARNING | LIBXML_NOERROR);
        libxml_clear_errors();
        $xp = new \DOMXPath($dom);
        $attr = fn (string $q) => array_map(fn ($n) => trim($n->nodeValue), iterator_to_array($xp->query($q)));
        $luar = fn (string $ref) => self::dasar(self::hostRef($ref, $host)) !== self::dasar($host);
        $rasio = function (array $refs, callable $buruk, int $a, int $b): string {
            if (! $refs) {
                return '!tidak ada elemen untuk dihitung';
            }
            $p = 100 * count(array_filter($refs, $buruk)) / count($refs);

            return $p < $a ? 'sah' : ($p <= $b ? 'curiga' : 'phishing');
        };

        $ikon = $attr("//link[contains(translate(@rel,'ICON','icon'),'icon')]/@href");
        $iframeTak = false;
        foreach ($xp->query('//iframe') as $f) {
            $iframeTak = $iframeTak || $f->getAttribute('frameborder') === '0' || $f->getAttribute('width') === '0' || $f->getAttribute('height') === '0'
                || preg_match('/display\s*:\s*none|visibility\s*:\s*hidden|(width|height)\s*:\s*0(px)?\s*(;|$)/i', $f->getAttribute('style'));
        }

        return [
            'Request_URL' => $rasio($attr('//img/@src | //audio/@src | //video/@src | //embed/@src | //source/@src'), $luar, 22, 61),
            'URL_of_Anchor' => $rasio($attr('//a/@href'), fn ($h) => $luar($h) || preg_match('~^(#$|#content|#skip|javascript:|$)~i', $h), 31, 67),
            'Links_in_tags' => $rasio($attr("//script/@src | //link/@href | //meta/@content[starts-with(.,'http') or starts-with(.,'//')]"), $luar, 17, 81),
            'Favicon' => $ikon ? ($luar($ikon[0]) ? 'phishing' : 'sah') : '!tidak ada tag favicon',
            'Submitting_to_email' => $xp->query("//form[contains(translate(@action,'MAILTO','mailto'),'mailto:')]")->length ? 'phishing' : 'sah',
            'on_mouseover' => preg_match('~onmouseover\s*=\s*["\'][^"\']*status\s*=~i', $html) ? 'phishing' : 'sah',
            'RightClick' => preg_match('~oncontextmenu\s*=\s*["\']?\s*return\s+false|event\.button\s*==\s*2~i', $html) ? 'phishing' : 'sah',
            'Iframe' => $iframeTak ? 'phishing' : 'sah',
        ];
    }
}
