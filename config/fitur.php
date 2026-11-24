<?php

// Teks dropdown: judul, arti nilai sah/curiga/phishing, dan cara mendapatkan datanya.
// Dirangkum dari "Phishing Websites Features.docx" (paket UCI 327); cocokkan lagi dengan dokumen itu.
// Fitur tanpa 'curiga' hanya punya dua nilai. Fitur 'Alamat' dihitung otomatis dari teks URL.
return [
    'sudah_isi_data' => ['judul' => 'Sudah memasukkan data'],
    'domain' => ['judul' => 'Domain ada di DNS'],

    // otomatis dari URL
    'having_IP_Address' => ['judul' => 'URL memakai alamat IP', 'grup' => 'Alamat'],
    'URL_Length' => ['judul' => 'Panjang URL', 'grup' => 'Alamat'],
    'Shortining_Service' => ['judul' => 'Memakai pemendek URL', 'grup' => 'Alamat'],
    'having_At_Symbol' => ['judul' => 'URL mengandung @', 'grup' => 'Alamat'],
    'double_slash_redirecting' => ['judul' => 'Tanda // di tengah URL', 'grup' => 'Alamat'],
    'Prefix_Suffix' => ['judul' => 'Tanda - pada domain', 'grup' => 'Alamat'],
    'having_Sub_Domain' => ['judul' => 'Jumlah subdomain', 'grup' => 'Alamat'],
    'HTTPS_token' => ['judul' => 'Kata "https" di nama domain', 'grup' => 'Alamat'],
    'port' => ['judul' => 'Port non-standar di URL', 'grup' => 'Alamat'],

    // manual: sertifikat
    'SSLfinal_State' => [
        'grup' => 'Sertifikat HTTPS',
        'judul' => 'Status HTTPS dan sertifikat',
        'sah' => 'HTTPS, penerbit sertifikat tepercaya, umur sertifikat 1 tahun atau lebih',
        'curiga' => 'HTTPS, tetapi penerbit sertifikat tidak dikenal',
        'phishing' => 'tanpa HTTPS atau sertifikat bermasalah',
        'cara' => 'Klik ikon gembok di bilah alamat lalu buka detail sertifikat: lihat penerbit dan tanggal terbit. Tanpa membuka situsnya, cari domain di crt.sh atau SSL Labs.',
    ],

    // manual: data domain
    'Domain_registeration_length' => [
        'grup' => 'Data domain',
        'judul' => 'Masa pendaftaran domain',
        'sah' => 'terdaftar sampai lebih dari 1 tahun ke depan',
        'phishing' => 'berakhir dalam 1 tahun atau kurang',
        'cara' => 'Cari domain di who.is atau lookup.icann.org, lalu baca tanggal kedaluwarsa (Expiry Date).',
    ],
    'age_of_domain' => [
        'grup' => 'Data domain',
        'judul' => 'Usia domain',
        'sah' => '6 bulan atau lebih',
        'phishing' => 'kurang dari 6 bulan',
        'cara' => 'Cari domain di who.is, lalu baca tanggal pembuatan (Creation Date).',
    ],
    'DNSRecord' => [
        'grup' => 'Data domain',
        'judul' => 'Catatan DNS domain',
        'sah' => 'domain punya catatan DNS',
        'phishing' => 'tidak ada catatan DNS',
        'cara' => 'Cari domain di dnschecker.org, atau jalankan "nslookup namadomain.com" di terminal.',
    ],
    'Abnormal_URL' => [
        'grup' => 'Data domain',
        'judul' => 'Kecocokan domain dengan data pemilik',
        'sah' => 'nama domain cocok dengan identitas pemilik di WHOIS',
        'phishing' => 'tidak cocok dengan identitas pemilik',
        'cara' => 'Lihat nama organisasi pemilik di who.is. Jika data pemilik disembunyikan, pilih "Tidak diketahui".',
    ],

    // manual: isi halaman. Aman: pakai urlscan.io (Requests, Links) atau lihat kode sumber hasil scan.
    'Favicon' => [
        'grup' => 'Isi halaman',
        'judul' => 'Ikon situs (favicon)',
        'sah' => 'dimuat dari domain sendiri',
        'phishing' => 'dimuat dari domain lain',
        'cara' => 'Di kode sumber cari <link rel="icon" href="...">, lihat domain pada alamatnya. Atau lihat daftar Requests di urlscan.io.',
    ],
    'Request_URL' => [
        'grup' => 'Isi halaman',
        'judul' => 'Gambar, audio, video dari domain lain',
        'sah' => 'kurang dari 22% berasal dari domain lain',
        'curiga' => '22% sampai 61%',
        'phishing' => 'lebih dari 61%',
        'cara' => 'Buka hasil scan di urlscan.io, tab Requests, lalu bandingkan jumlah yang berasal dari domain lain dengan totalnya.',
    ],
    'URL_of_Anchor' => [
        'grup' => 'Isi halaman',
        'judul' => 'Tautan yang menuju domain lain atau kosong',
        'sah' => 'kurang dari 31% tautan',
        'curiga' => '31% sampai 67%',
        'phishing' => 'lebih dari 67% (termasuk tautan # atau javascript:void(0))',
        'cara' => 'Di urlscan.io lihat daftar Links, atau di kode sumber cari "<a href" lalu hitung perkiraan persentasenya.',
    ],
    'Links_in_tags' => [
        'grup' => 'Isi halaman',
        'judul' => 'Tautan di tag meta, script, link ke domain lain',
        'sah' => 'kurang dari 17%',
        'curiga' => '17% sampai 81%',
        'phishing' => 'lebih dari 81%',
        'cara' => 'Di kode sumber cari tag <meta>, <script src>, dan <link href>, lalu lihat berapa yang menuju domain lain.',
    ],
    'SFH' => [
        'grup' => 'Isi halaman',
        'judul' => 'Tujuan pengiriman form',
        'sah' => 'form dikirim ke domain sendiri',
        'curiga' => 'form dikirim ke domain lain',
        'phishing' => 'tujuan form kosong atau about:blank',
        'cara' => 'Di kode sumber cari <form action="...">. Jika halaman tidak punya form, biarkan "Tidak diketahui".',
    ],
    'Submitting_to_email' => [
        'grup' => 'Isi halaman',
        'judul' => 'Form mengirim data ke email',
        'sah' => 'tidak ada',
        'phishing' => 'form memakai mailto: atau mail()',
        'cara' => 'Di kode sumber cari kata "mailto:" atau "mail(".',
    ],

    // manual: perilaku halaman
    'Redirect' => [
        'grup' => 'Perilaku halaman',
        'judul' => 'Jumlah pengalihan halaman',
        'sah' => '1 kali atau kurang',
        'curiga' => '2 sampai 3 kali',
        'phishing' => '4 kali atau lebih',
        'cara' => 'Scan di urlscan.io dan lihat rantai redirect, atau pakai pemeriksa redirect online.',
    ],
    'on_mouseover' => [
        'grup' => 'Perilaku halaman',
        'judul' => 'Mouse di atas tautan mengubah bilah status',
        'sah' => 'tidak berubah',
        'phishing' => 'mengubah teks bilah status',
        'cara' => 'Di kode sumber cari "onMouseOver".',
    ],
    'RightClick' => [
        'grup' => 'Perilaku halaman',
        'judul' => 'Klik kanan dinonaktifkan',
        'sah' => 'klik kanan normal',
        'phishing' => 'klik kanan dinonaktifkan',
        'cara' => 'Di kode sumber cari "contextmenu" atau "event.button==2".',
    ],
    'popUpWidnow' => [
        'grup' => 'Perilaku halaman',
        'judul' => 'Pop-up berisi kolom isian',
        'sah' => 'tidak ada',
        'phishing' => 'pop-up meminta data',
        'cara' => 'Di kode sumber cari "window.open" lalu lihat apakah isinya kolom isian.',
    ],
    'Iframe' => [
        'grup' => 'Perilaku halaman',
        'judul' => 'Iframe tersembunyi',
        'sah' => 'tidak ada',
        'phishing' => 'ada iframe tak terlihat (frameBorder 0 atau ukuran 0)',
        'cara' => 'Di kode sumber cari "<iframe".',
    ],

    // manual: reputasi
    'web_traffic' => [
        'grup' => 'Reputasi',
        'judul' => 'Peringkat lalu lintas situs',
        'sah' => 'peringkat di bawah 100.000',
        'curiga' => 'peringkat di atas 100.000',
        'phishing' => 'tidak masuk peringkat',
        'cara' => 'Cari domain di daftar peringkat Tranco (tranco-list.eu). Alexa sudah ditutup.',
    ],
    'Page_Rank' => [
        'grup' => 'Reputasi',
        'judul' => 'PageRank',
        'sah' => 'PageRank 0,2 atau lebih',
        'phishing' => 'di bawah 0,2',
        'cara' => 'PageRank Google sudah tidak publik. Coba Open PageRank jika masih tersedia, atau pilih "Tidak diketahui".',
    ],
    'Google_Index' => [
        'grup' => 'Reputasi',
        'judul' => 'Terindeks Google',
        'sah' => 'muncul di hasil pencarian',
        'phishing' => 'tidak muncul',
        'cara' => 'Ketik site:namadomain.com di Google. Situs phishing baru sering belum terindeks.',
    ],
    'Links_pointing_to_page' => [
        'grup' => 'Reputasi',
        'judul' => 'Tautan masuk dari situs lain',
        'sah' => 'lebih dari 2 tautan',
        'curiga' => '1 sampai 2 tautan',
        'phishing' => 'tidak ada',
        'cara' => 'Pakai pemeriksa backlink gratis (mis. Ahrefs Backlink Checker).',
    ],
    'Statistical_report' => [
        'grup' => 'Reputasi',
        'judul' => 'Ada di daftar laporan phishing',
        'sah' => 'tidak ditemukan',
        'phishing' => 'domain atau IP ada di daftar phishing',
        'cara' => 'Cari URL di VirusTotal atau daftar phishing publik seperti OpenPhish.',
    ],
];
