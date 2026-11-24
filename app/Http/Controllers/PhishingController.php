<?php

namespace App\Http\Controllers;

use App\Services\Pemeriksa;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class PhishingController extends Controller
{
    public function __invoke(Request $r)
    {
        if (! $r->isMethod('post')) {
            return view('phishing');
        }

        $url = $r->validate(['url' => 'required|string|max:2000', 'm' => 'nullable|array'])['url'];
        $aturan = array_merge(config('pohon.aturan', []), config('pakar'));

        $auto = $r->boolean('otomatis') ? Pemeriksa::periksa($url) : null;
        // Isian dropdown hanya berlaku untuk URL yang sama dengan hasil sebelumnya, dan hanya bila nilainya berbeda
        // dari yang terisi otomatis waktu itu (a[...]); selebihnya dianggap sisa hasil lama dan dibuang.
        $lama = $r->input('url_asal') === $url;
        $a = (array) $r->input('a');
        $manual = $lama ? array_filter((array) $r->input('m'), fn ($v, $f) => in_array($v, ['sah', 'curiga', 'phishing'], true) && ($a[$f] ?? null) !== $v, ARRAY_FILTER_USE_BOTH) : [];
        $manual += $auto['nilai'] ?? [];

        return view('phishing', self::analisis($url, $r->boolean('sudah_isi_data'), $manual, $aturan, ($auto['domain']['ada'] ?? true) ? [] : ['domain=tidak_ada']) + ['nilai' => $manual, 'auto' => $auto]);
    }

    public static function analisis(string $url, bool $isiData, array $manual, array $rules, array $tambahan = []): array
    {
        $awal = $fakta = array_merge(self::fakta($url, $isiData, $manual), $tambahan);
        $jejak = [];
        self::chain($fakta, $rules, $jejak);

        $e = null;
        if (! preg_grep('/^kelas=/', $fakta)) { // ciri belum cukup untuk satu pun aturan: pakai perkiraan
            $e = self::perkiraan($fakta, $rules);
            $kelas = ! $e ? 'belum_pasti' : ($e['p'] >= 0.7 ? 'phishing' : ($e['p'] <= 0.3 ? 'aman' : 'belum_pasti'));
            $fakta[] = "kelas=$kelas";
            self::chain($fakta, $rules, $jejak);
        }

        $pilih = fn ($k, $urut) => current(array_filter($urut, fn ($v) => in_array("$k=$v", $fakta)));

        return [
            'fakta' => $awal,
            'perkiraan' => $e,
            'kelas' => $pilih('kelas', ['phishing', 'mencurigakan', 'aman', 'belum_pasti']),
            'risiko' => $pilih('risiko', ['tinggi', 'sedang', 'rendah', 'belum_diketahui']),
            'saran' => array_values(array_map(fn ($f) => substr($f, 6), preg_grep('/^saran=/', $fakta))),
            'jejak' => array_map(fn ($id) => "$id: IF ".implode(' AND ', $rules[$id][0]).' THEN '.$rules[$id][1], array_keys($jejak)),
        ];
    }

    // Fitur otomatis dari teks URL (kode nilai sama dengan dataset UCI) + fitur manual dari dropdown.
    // ponytail: having_Sub_Domain tidak membedakan ccTLD ganda (co.id); tambahkan daftar public suffix bila perlu.
    public static function fakta(string $url, bool $isiData, array $manual = []): array
    {
        $url = trim($url);
        if (! preg_match('~^[a-z][a-z0-9+.-]*://~i', $url)) {
            $url = 'http://'.$url;
        }
        $p = parse_url($url);
        $host = strtolower($p['host'] ?? '');
        if ($host === '') {
            throw ValidationException::withMessages(['url' => 'URL tidak valid.']);
        }
        $len = strlen($url);
        $titik = substr_count(preg_replace('/^www\./', '', $host), '.');

        $auto = [
            'having_IP_Address' => filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) ? -1 : 1,
            'URL_Length' => $len < 54 ? 1 : ($len <= 75 ? 0 : -1),
            'Shortining_Service' => in_array($host, ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly']) ? -1 : 1,
            'having_At_Symbol' => str_contains($url, '@') ? -1 : 1,
            'double_slash_redirecting' => strrpos($url, '//') > 7 ? -1 : 1,
            'Prefix_Suffix' => str_contains($host, '-') ? -1 : 1,
            'having_Sub_Domain' => $titik <= 1 ? 1 : ($titik == 2 ? 0 : -1),
            'HTTPS_token' => str_contains($host, 'https') ? -1 : 1,
            'port' => isset($p['port']) && ! in_array($p['port'], [80, 443]) ? -1 : 1,
        ];
        $kata = [-1 => 'phishing', 0 => 'curiga', 1 => 'sah'];
        $fakta = [];
        foreach ($auto as $f => $v) {
            $fakta[] = "$f={$kata[$v]}";
        }
        foreach ($manual as $f => $v) { // dropdown: kosong = tidak diketahui, tidak jadi fakta
            if (in_array($v, $kata, true) && preg_match('/^\w+$/', (string) $f)) {
                $fakta[] = "$f=$v";
            }
        }
        if ($isiData) {
            $fakta[] = 'sudah_isi_data=ya';
        }

        return $fakta;
    }

    // Perkiraan saat ciri manual belum lengkap: gabungkan semua daun aturan yang tidak bertentangan dengan
    // fakta yang ada, berbobot jumlah data latih (cara C4.5 menangani nilai hilang).
    // Mengembalikan p = kemungkinan phishing dan 'kosong' = ciri belum terisi yang paling menentukan.
    private static function perkiraan(array $fakta, array $rules): ?array
    {
        $tahu = [];
        foreach ($fakta as $f) {
            [$k, $v] = explode('=', $f, 2);
            $tahu[$k] = $v;
        }
        $n = $ph = 0;
        $kosong = [];
        foreach ($rules as $r) {
            if (empty($r[2])) {
                continue;
            }
            $hilang = [];
            foreach ($r[0] as $c) {
                [$k, $vs] = explode('=', $c, 2);
                if (! isset($tahu[$k])) {
                    $hilang[] = $k;
                } elseif (! in_array($tahu[$k], explode('|', $vs))) {
                    continue 2; // daun ini bertentangan dengan fakta
                }
            }
            $n += $r[2][0];
            $ph += $r[2][0] * $r[2][1];
            array_push($kosong, ...$hilang);
        }
        if (! $n) {
            return null;
        }
        $hitung = array_count_values($kosong);
        arsort($hitung);

        return ['p' => $ph / $n, 'kosong' => array_slice(array_keys($hitung), 0, 3)];
    }

    // Satu syarat "fitur=a|b" terpenuhi bila salah satu nilainya ada di memori kerja.
    private static function cocok(array $if, array $fakta): bool
    {
        foreach ($if as $c) {
            [$k, $vs] = explode('=', $c, 2);
            foreach (explode('|', $vs) as $v) {
                if (in_array("$k=$v", $fakta)) {
                    continue 2;
                }
            }

            return false;
        }

        return true;
    }

    // Forward chaining: ulangi sampai tidak ada aturan baru yang terpenuhi.
    private static function chain(array &$fakta, array $rules, array &$jejak): void
    {
        do {
            $baru = false;
            foreach ($rules as $id => [$if, $then]) {
                if (isset($jejak[$id]) || ! self::cocok($if, $fakta)) {
                    continue;
                }
                $jejak[$id] = true;
                if (! in_array($then, $fakta)) {
                    $fakta[] = $then;
                }
                $baru = true;
            }
        } while ($baru);
    }
}
