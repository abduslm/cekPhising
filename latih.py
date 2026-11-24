"""Latih decision tree dari dataset UCI Phishing Websites -> config/pohon.php.
Pakai (dari root proyek Laravel): python latih.py "Training Dataset.arff"   (file .csv juga bisa)
Kolom 'Result': -1 = phishing, 1 = sah. Nilai fitur: -1 phishing, 0 curiga, 1 sah."""
import sys
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

# Fitur yang dihitung otomatis dari teks URL di PhishingController::fakta()
AUTO = {"having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
        "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "HTTPS_token", "port"}
# Nama kanonik yang dipakai controller PHP. UCI menulisnya huruf kecil semua, jadi dicocokkan tanpa membedakan huruf.
CANON = ["having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol", "double_slash_redirecting",
         "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length", "Favicon", "port",
         "HTTPS_token", "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
         "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain", "DNSRecord",
         "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report", "Result"]
KATA = {-1: "phishing", 0: "curiga", 1: "sah"}
MAX_DEPTH, MIN_LEAF = 5, 30  # makin kecil, makin ringkas aturannya



def baca(path):
    if path.lower().endswith(".arff"):  # ARFF = CSV + header @attribute; nilai nominal terbaca sebagai bytes
        from scipy.io import arff
        return pd.DataFrame(arff.loadarff(path)[0]).apply(lambda s: s.map(int))
    return pd.read_csv(path)


df = baca(sys.argv[1]).drop(columns=["Index"], errors="ignore")
kanon = {c.lower(): c for c in CANON}
df.columns = [kanon.get(k.strip().lower(), k) for k in df.columns]
print("jumlah per kelas:", df["Result"].value_counts().to_dict(), "(pastikan -1 = phishing, 1 = sah)")
X, y = df.drop(columns="Result"), (df["Result"] == -1).astype(int)  # 1 = phishing
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=0, stratify=y)
m = DecisionTreeClassifier(max_depth=MAX_DEPTH, min_samples_leaf=MIN_LEAF, random_state=0).fit(Xtr, ytr)
print(f"akurasi data uji: {m.score(Xte, yte):.3f}")

t, cols = m.tree_, list(X.columns)


def walk(n=0, allow={}):
    """Satu jalur akar-ke-daun = satu aturan; syarat tiap fitur = himpunan nilai yang diizinkan."""
    if t.children_left[n] == -1:
        v = t.value[n][0]
        yield allow, v[1] / v.sum(), int(t.n_node_samples[n])
        return
    f, th = cols[t.feature[n]], t.threshold[n]
    cur = allow.get(f, {-1, 0, 1})
    kiri, kanan = {v for v in cur if v <= th}, {v for v in cur if v > th}
    if kiri:
        yield from walk(t.children_left[n], {**allow, f: kiri})
    if kanan:
        yield from walk(t.children_right[n], {**allow, f: kanan})


rules, manual = [], set()
for allow, p, n in walk():
    conds = [f"{f}=" + "|".join(KATA[v] for v in sorted(s, reverse=True)) for f, s in sorted(allow.items())]
    if not conds:
        continue
    manual |= {f for f in allow if f not in AUTO}
    rules.append((conds, "phishing" if p >= 0.7 else "aman" if p <= 0.3 else "mencurigakan", n, p))

with open("config/pohon.php", "w") as o:
    o.write("<?php\n\n// Dibuat oleh latih.py dari dataset, jangan diedit manual.\nreturn [\n")
    o.write(f"    'manual' => {sorted(manual)!r},\n    'aturan' => [\n")
    for i, (c, k, n, p) in enumerate(rules, 1):  # elemen ke-3 [jumlah data, proporsi phishing] dipakai untuk perkiraan
        o.write(f"        'T{i}' => [{c!r}, 'kelas={k}', [{n}, {p:.3f}]],\n")
    o.write("    ],\n];\n")
print(f"{len(rules)} aturan ditulis ke config/pohon.php; fitur manual: {sorted(manual)}")
