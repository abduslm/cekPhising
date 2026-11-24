<?php

// Basis aturan: id => [syarat IF (semua harus ada), fakta THEN].
// Aturan klasifikasi (T*) ada di config/pohon.php hasil latih.py. Di sini: risiko dan saran.
return [
    // kelas -> risiko
    'R15' => [['kelas=phishing'], 'risiko=tinggi'],
    'R16' => [['kelas=mencurigakan'], 'risiko=sedang'],
    'R17' => [['kelas=aman'], 'risiko=rendah'],
    'R25' => [['kelas=belum_pasti'], 'risiko=belum_diketahui'],

    // kelas (+ jawaban pengguna) -> saran
    'R18' => [['kelas=phishing'], 'saran=Tutup halaman ini. Jangan isi data apa pun dan jangan klik tautan lain di dalamnya.'],
    'R19' => [['kelas=phishing'], 'saran=Laporkan URL ke Google Safe Browsing dan peringatkan orang yang menerima tautan yang sama.'],
    'R20' => [['kelas=phishing', 'sudah_isi_data=ya'], 'saran=Segera ganti password akun terkait, aktifkan verifikasi dua langkah, dan periksa aktivitas login yang mencurigakan.'],
    'R21' => [['kelas=phishing', 'sudah_isi_data=ya'], 'saran=Jika data kartu atau rekening ikut terkirim, hubungi bank Anda sekarang untuk memblokirnya.'],
    'R22' => [['kelas=mencurigakan'], 'saran=Jangan masukkan data sensitif. Buka situs resminya dengan mengetik alamat sendiri, lalu bandingkan domainnya.'],
    'R23' => [['kelas=mencurigakan', 'sudah_isi_data=ya'], 'saran=Karena data sudah terkirim, ganti password sebagai tindakan berjaga-jaga.'],
    'R26' => [['kelas=belum_pasti'], 'saran=Aturan belum cukup data untuk memutuskan. Isi dropdown fitur yang bisa Anda periksa, atau cek lewat sumber resmi.'],
    'R27' => [['domain=tidak_ada'], 'saran=Domain ini tidak ditemukan di DNS: salah ketik, sudah dimatikan, atau belum aktif. Periksa ejaannya dan jangan memasukkan data apa pun.'],
    'R24' => [['kelas=aman'], 'saran=Tidak ada tanda jelas phishing. Tetap periksa ejaan domain sebelum memasukkan data.'],
];
