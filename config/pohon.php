<?php

// Dibuat oleh latih.py dari dataset, jangan diedit manual.
return [
    'manual' => ['Domain_registeration_length', 'Google_Index', 'Links_in_tags', 'Links_pointing_to_page', 'Request_URL', 'SSLfinal_State', 'URL_of_Anchor', 'web_traffic'],
    'aturan' => [
        'T1' => [['SSLfinal_State=curiga|phishing', 'URL_of_Anchor=phishing'], 'kelas=phishing', [2416, 1.000]],
        'T2' => [['Links_in_tags=phishing', 'Links_pointing_to_page=curiga|phishing', 'SSLfinal_State=curiga|phishing', 'URL_of_Anchor=sah|curiga', 'having_IP_Address=curiga|phishing'], 'kelas=phishing', [132, 1.000]],
        'T3' => [['Links_in_tags=phishing', 'Links_pointing_to_page=sah', 'SSLfinal_State=curiga|phishing', 'URL_of_Anchor=sah|curiga', 'having_IP_Address=curiga|phishing'], 'kelas=phishing', [127, 0.874]],
        'T4' => [['Links_in_tags=phishing', 'SSLfinal_State=curiga|phishing', 'URL_of_Anchor=sah|curiga', 'having_IP_Address=sah', 'having_Sub_Domain=phishing'], 'kelas=phishing', [217, 0.889]],
        'T5' => [['Links_in_tags=phishing', 'SSLfinal_State=curiga|phishing', 'URL_of_Anchor=sah|curiga', 'having_IP_Address=sah', 'having_Sub_Domain=sah|curiga'], 'kelas=phishing', [239, 0.749]],
        'T6' => [['Domain_registeration_length=curiga|phishing', 'Links_in_tags=sah|curiga', 'Prefix_Suffix=curiga|phishing', 'SSLfinal_State=curiga|phishing', 'URL_of_Anchor=sah|curiga'], 'kelas=mencurigakan', [381, 0.446]],
        'T7' => [['Domain_registeration_length=sah', 'Links_in_tags=sah|curiga', 'Prefix_Suffix=curiga|phishing', 'SSLfinal_State=curiga|phishing', 'URL_of_Anchor=sah|curiga'], 'kelas=phishing', [213, 0.765]],
        'T8' => [['Links_in_tags=sah|curiga', 'Prefix_Suffix=sah', 'SSLfinal_State=curiga|phishing', 'URL_of_Anchor=sah|curiga'], 'kelas=aman', [65, 0.000]],
        'T9' => [['Request_URL=curiga|phishing', 'SSLfinal_State=sah', 'URL_of_Anchor=phishing'], 'kelas=phishing', [108, 1.000]],
        'T10' => [['Links_in_tags=phishing', 'Request_URL=sah', 'SSLfinal_State=sah', 'URL_of_Anchor=phishing'], 'kelas=phishing', [59, 0.898]],
        'T11' => [['Links_in_tags=sah|curiga', 'Request_URL=sah', 'SSLfinal_State=sah', 'URL_of_Anchor=phishing'], 'kelas=mencurigakan', [42, 0.476]],
        'T12' => [['Google_Index=curiga|phishing', 'SSLfinal_State=sah', 'URL_of_Anchor=sah|curiga', 'web_traffic=phishing'], 'kelas=aman', [52, 0.077]],
        'T13' => [['Google_Index=sah', 'SSLfinal_State=sah', 'URL_of_Anchor=sah|curiga', 'web_traffic=phishing'], 'kelas=aman', [672, 0.009]],
        'T14' => [['SSLfinal_State=sah', 'URL_of_Anchor=sah|curiga', 'having_Sub_Domain=curiga|phishing', 'web_traffic=curiga'], 'kelas=mencurigakan', [371, 0.461]],
        'T15' => [['SSLfinal_State=sah', 'URL_of_Anchor=sah|curiga', 'having_Sub_Domain=sah', 'web_traffic=curiga'], 'kelas=aman', [471, 0.153]],
        'T16' => [['Links_in_tags=phishing', 'SSLfinal_State=sah', 'URL_of_Anchor=sah|curiga', 'having_Sub_Domain=curiga|phishing', 'web_traffic=sah'], 'kelas=aman', [464, 0.170]],
        'T17' => [['Links_in_tags=phishing', 'SSLfinal_State=sah', 'URL_of_Anchor=sah|curiga', 'having_Sub_Domain=sah', 'web_traffic=sah'], 'kelas=aman', [390, 0.021]],
        'T18' => [['Links_in_tags=sah|curiga', 'SSLfinal_State=sah', 'URL_of_Anchor=sah|curiga', 'having_IP_Address=curiga|phishing', 'web_traffic=sah'], 'kelas=aman', [634, 0.032]],
        'T19' => [['Links_in_tags=sah|curiga', 'SSLfinal_State=sah', 'URL_of_Anchor=sah|curiga', 'having_IP_Address=sah', 'web_traffic=sah'], 'kelas=aman', [1791, 0.007]],
    ],
];
