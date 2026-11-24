<?php

namespace Tests\Feature;

use App\Http\Controllers\PhishingController as P;
use App\Services\Pemeriksa;
use Tests\TestCase;

class PhishingTest extends TestCase
{
    public function test_aturan_pohon_risiko_dan_saran(): void
    {
        $r = array_merge([
            'T1' => [['having_IP_Address=phishing'], 'kelas=phishing'],
            'T2' => [['having_IP_Address=sah', 'SSLfinal_State=sah|curiga'], 'kelas=aman'],
        ], config('pakar'));

        $a = P::analisis('http://192.168.0.1/login', true, [], $r);
        $this->assertSame(['phishing', 'tinggi'], [$a['kelas'], $a['risiko']]);
        $this->assertStringContainsString('ganti password', implode(' ', $a['saran']));

        $this->assertSame('aman', P::analisis('https://www.wikipedia.org', false, ['SSLfinal_State' => 'sah'], $r)['kelas']);
        $this->assertSame('belum_pasti', P::analisis('https://www.wikipedia.org', false, [], $r)['kelas']); // fitur manual kosong
    }

    public function test_perkiraan_dari_daun_yang_tidak_bertentangan(): void
    {
        $r = array_merge([
            'T1' => [['having_IP_Address=sah', 'SSLfinal_State=sah|curiga'], 'kelas=aman', [100, 0.05]],
            'T2' => [['having_IP_Address=sah', 'SSLfinal_State=phishing'], 'kelas=phishing', [10, 0.9]],
        ], config('pakar'));

        $a = P::analisis('https://www.wikipedia.org', false, [], $r); // SSL tidak diisi
        $this->assertSame('aman', $a['kelas']);
        $this->assertEqualsWithDelta(0.127, $a['perkiraan']['p'], 0.001);
        $this->assertSame(['SSLfinal_State'], $a['perkiraan']['kosong']);
    }

    public function test_halaman_terbuka(): void
    {
        $this->get('/')->assertOk()->assertSee('Ambil ciri otomatis');
        // tanpa centang "otomatis" tidak ada akses jaringan
        $this->post('/', ['url' => 'http://192.168.0.1'])->assertOk()->assertSee('Tingkat risiko');
    }

    public function test_ciri_dari_html(): void
    {
        $h = Pemeriksa::isi('<img src="/a.png"><img src="https://cdn.lain.com/b.png">'
            .'<a href="#">1</a><a href="javascript:void(0)">2</a><a href="https://lain.com">3</a><a href="/ok">4</a>'
            .'<form action="MAILTO:a@b.c"></form>', 'www.contoh.com');

        $this->assertSame('curiga', $h['Request_URL']); // 1 dari 2 berasal dari domain lain = 50%
        $this->assertSame('phishing', $h['URL_of_Anchor']); // 3 dari 4 kosong/luar = 75%
        $this->assertSame('phishing', $h['Submitting_to_email']);
        $this->assertSame('sah', $h['Iframe']);
        $this->assertStringStartsWith('!', $h['Links_in_tags']); // tidak ada elemen: gagal, bukan sah
    }

    public function test_domain_tidak_ada_jadi_fakta_dan_saran(): void
    {
        $a = P::analisis('http://tidak-ada.test', false, [], config('pakar'), ['domain=tidak_ada']);
        $this->assertContains('domain=tidak_ada', $a['fakta']);
        $this->assertStringContainsString('tidak ditemukan di DNS', implode(' ', $a['saran']));
    }

    public function test_alamat_internal_tidak_dibuka(): void
    {
        $a = Pemeriksa::periksa('http://127.0.0.1/admin'); // semua pemeriksa menolak sebelum menyentuh jaringan
        $this->assertSame([], $a['nilai']);
        $this->assertArrayHasKey('SSLfinal_State', $a['gagal']);
        $this->assertArrayHasKey('Redirect', $a['gagal']);
    }
}
