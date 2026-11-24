<!doctype html>
<html lang="id">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sistem Pakar Deteksi Phishing</title>
<style>
:root{--bg:#f3f5f8;--card:#fff;--ink:#1b2430;--mute:#5c6876;--line:#d3dae1;--acc:#0f6e8c;--accink:#fff;
--phishing:#b3261e;--mencurigakan:#a8700a;--aman:#17734a;--belum_pasti:#5c6876;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#141a21;--card:#1d2530;--ink:#e6ebf0;--mute:#98a4b1;--line:#334050;--acc:#5bc0de;--accink:#0b1a22;
--phishing:#ff8a80;--mencurigakan:#e0a82e;--aman:#5fd39a;--belum_pasti:#98a4b1}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:1.5rem 1rem 3rem}
h1{font-size:1.7rem;margin:0 0 .25rem}
.sub{color:var(--mute);margin:0 0 1.2rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:1rem;margin-bottom:1rem}
input[type=text],select{width:100%;padding:.6rem;font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:6px}
button{background:var(--acc);color:var(--accink);border:0;border-radius:6px;padding:.7rem 1.4rem;font:inherit;font-weight:600;cursor:pointer}
:focus-visible{outline:3px solid var(--acc);outline-offset:2px}
.aman-info{font-size:.9rem;color:var(--mute);border-left:4px solid var(--mencurigakan);padding-left:.75rem;margin:1rem 0}
.hasil{border-width:3px}
.hasil h2{margin:0;font-size:1.6rem}
.hasil.phishing{border-color:var(--phishing)}.hasil.phishing h2{color:var(--phishing)}
.hasil.mencurigakan{border-color:var(--mencurigakan)}.hasil.mencurigakan h2{color:var(--mencurigakan)}
.hasil.aman{border-color:var(--aman)}.hasil.aman h2{color:var(--aman)}
.hasil.belum_pasti{border-color:var(--belum_pasti)}
.grup>summary{font-weight:600;cursor:pointer;padding:.4rem 0}
.f{margin:.9rem 0}
.f label{display:block;font-weight:600;margin-bottom:.25rem}
.cara{font-size:.88rem;color:var(--mute);margin-top:.3rem}
.cara summary{cursor:pointer;color:var(--acc)}
.b{display:inline-block;font-size:.8rem;border:1px solid var(--line);border-radius:99px;padding:.1rem .6rem;margin:.15rem .1rem}
.b.phishing{border-color:var(--phishing)}.b.curiga{border-color:var(--mencurigakan)}.b.sah{border-color:var(--aman)}
code{font-size:.82em}
.err{color:var(--phishing)}
</style>
<main>
<h1>Deteksi Phishing</h1>
<p class="sub">Masukkan alamat situs. Ciri dibaca otomatis dari teks URL dan dari internet (DNS, RDAP, sertifikat HTTPS, isi halaman, Tranco). Ciri yang gagal diambil bisa Anda isi manual.</p>

@isset($kelas)
<section class="card hasil {{ $kelas }}" id="hasil" aria-live="polite">
    <h2>{{ strtoupper(str_replace('_', ' ', $kelas)) }}</h2>
    <p>Tingkat risiko: <b>{{ str_replace('_', ' ', $risiko) }}</b></p>
    @if(! empty($auto['domain']))
    <p class="aman-info" style="border-color:var(--{{ $auto['domain']['ada'] ? 'aman' : 'phishing' }})">
        @if($auto['domain']['ada'])Domain ditemukan di DNS{{ $auto['domain']['terdaftar'] ? ' dan terdaftar di RDAP' : '' }}.
        @else Domain <b>tidak ditemukan</b> di DNS{{ $auto['domain']['terdaftar'] === true ? ', tetapi masih terdaftar di RDAP (nonaktif atau diparkir)' : ($auto['domain']['terdaftar'] === false ? ' dan tidak terdaftar di RDAP' : '') }}.
        @endif</p>
    @endif
    @if($perkiraan)
    <p class="aman-info">Ini perkiraan karena sebagian ciri belum terisi. Kemungkinan phishing sekitar <b>{{ round($perkiraan['p'] * 100) }}%</b>.
        @if($perkiraan['kosong'])Isi ciri ini agar lebih pasti: {{ implode(', ', array_map(fn ($f) => config("fitur.$f.judul", $f), $perkiraan['kosong'])) }}.@endif</p>
    @endif
    <h3>Yang sebaiknya Anda lakukan</h3>
    <ol>@foreach($saran as $s)<li>{{ $s }}</li>@endforeach</ol>
    <details>
        <summary>Mengapa hasilnya begini?</summary>
        <p>Ciri yang terbaca:</p>
        <p>
            @foreach($fakta as $f)
            @php [$k, $v] = explode('=', $f, 2); @endphp
            <span class="b {{ $v }}">{{ config("fitur.$k.judul", $k) }}: {{ $v }}</span>
            @endforeach
        </p>
        <p>Aturan yang terpakai:</p>
        <ul>@foreach($jejak as $j)<li><code>{{ $j }}</code></li>@endforeach</ul>
    </details>
    <p><small>Hasil bisa keliru. Pastikan lewat sumber resmi sebelum memasukkan data.</small></p>
</section>
@endisset

<form method="post" action="/#hasil">
    @csrf
    <div class="card">
        <label for="url"><b>Alamat situs (URL)</b></label>
        <input type="text" id="url" name="url" value="{{ old('url', request('url')) }}" placeholder="https://contoh.com/login" inputmode="url" autocomplete="off" required>
        @error('url')<p class="err">{{ $message }}</p>@enderror
        <p><label><input type="checkbox" name="sudah_isi_data" value="1" @checked(old('sudah_isi_data', request('sudah_isi_data')))> Saya sudah terlanjur memasukkan data (password, kartu, OTP) di situs ini</label></p>
        <p><label><input type="checkbox" name="otomatis" value="1" @checked(! request()->isMethod('post') || request('otomatis'))> Ambil ciri otomatis dari internet</label><br>
            <small class="sub">Server kami yang membuka situs itu, bukan peramban Anda. Bisa makan beberapa detik. Hilangkan centang bila situs itu tidak boleh dibuka dari server.</small></p>
        @isset($kelas)<input type="hidden" name="url_asal" value="{{ request('url') }}">@endisset
        <button>Periksa</button>
    </div>

    @php $grup = collect(config('pohon.manual', []))->groupBy(fn ($f) => config("fitur.$f.grup", 'Lainnya')); @endphp
    @if($grup->isEmpty())
    <p class="card"><small>Belum ada aturan dari dataset. Jalankan <code>python latih.py "Training Dataset.arff"</code> lebih dulu.</small></p>
    @else
    <div class="card">
        <h2 style="margin-top:0">Ciri tambahan (opsional)</h2>
        <p class="sub">Makin banyak yang terisi, makin yakin hasilnya. Isian Anda menggantikan hasil otomatis. Jika tidak bisa memeriksanya, biarkan <b>Tidak diketahui</b>.</p>
        @isset($auto)
        @php $kurang = collect(config('pohon.manual', []))->filter(fn ($f) => empty($nilai[$f]))->map(fn ($f) => config("fitur.$f.judul", $f)); @endphp
        <p class="aman-info">Ciri yang terisi otomatis: {{ count($auto['nilai']) }}.
            @if($kurang->isEmpty())Semua ciri yang dibutuhkan aturan sudah terisi.@else Belum terisi dan perlu Anda isi manual: {{ $kurang->implode(', ') }}.@endif</p>
        @endisset
        <p class="aman-info">Jangan membuka situs yang dicurigai langsung di peramban Anda. Periksa lewat layanan seperti urlscan.io atau VirusTotal, yang membuka situsnya untuk Anda. Pilih mode scan privat jika URL memuat data pribadi.</p>

        @foreach($grup as $nama => $fs)
        @php $buka = collect($fs)->contains(fn ($f) => ! empty($nilai[$f] ?? old("m.$f")) || (isset($auto) && empty($nilai[$f]))); @endphp
        <details class="grup" {{ $buka ? 'open' : '' }}>
            <summary>{{ $nama }} ({{ count($fs) }} ciri)</summary>
            @foreach($fs as $f)
            @php $x = config("fitur.$f", []); @endphp
            <div class="f">
                <label for="m_{{ $f }}">{{ $x['judul'] ?? $f }}</label>
                <input type="hidden" name="a[{{ $f }}]" value="{{ $auto['nilai'][$f] ?? '' }}">
                <select id="m_{{ $f }}" name="m[{{ $f }}]">
                    <option value="">Tidak diketahui</option>
                    @foreach(['sah', 'curiga', 'phishing'] as $o)
                    @if(isset($x[$o]) || ! isset($x['sah']))
                    <option value="{{ $o }}" @selected(($nilai[$f] ?? old("m.$f")) === $o)>{{ ucfirst($o) }}{{ isset($x[$o]) ? ': '.$x[$o] : '' }}</option>
                    @endif
                    @endforeach
                </select>
                @isset($auto)
                    @if(isset($auto['nilai'][$f]) && ($nilai[$f] ?? null) === $auto['nilai'][$f])
                    <p class="cara">Terisi otomatis. Anda bisa mengubahnya.</p>
                    @elseif(empty($nilai[$f]))
                    <p class="cara err">Tidak terisi otomatis: {{ $auto['gagal'][$f] ?? 'tidak ada sumber data otomatis' }}. Isi manual bila bisa.</p>
                    @endif
                @endisset
                @isset($x['cara'])
                <details class="cara"><summary>Cara memeriksa</summary><p>{{ $x['cara'] }}</p></details>
                @endisset
            </div>
            @endforeach
        </details>
        @endforeach
        <p><button>Periksa</button></p>
    </div>
    @endif
</form>
<script>
document.querySelector('form').addEventListener('submit', e => e.target.querySelectorAll('button').forEach(b => { b.disabled = true; b.textContent = 'Memeriksa…'; }));
</script>
</main>
</html>
