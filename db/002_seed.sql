-- FT-28 uchun ma'lumotnoma. DIQQAT: moddalar sarlavhalari amaldagi tahrir
-- bo'yicha lex.uz dan tasdiqlanishi shart (TZ, 9.1-band).

INSERT INTO legal_articles (code, chapter, title_uz, severity, notes) VALUES
 ('278-1', 'XX-1', 'Kompyuter axborotiga qonunga xilof ravishda kirish',              'medium', 'lex.uz bo''yicha tekshirilsin'),
 ('278-2', 'XX-1', 'Axborot tizimi yoki tarmog''i ishiga noqonuniy aralashuv',        'medium', 'lex.uz bo''yicha tekshirilsin'),
 ('278-3', 'XX-1', 'Zararli dasturlarni yaratish yoki tarqatish',                     'high',   'lex.uz bo''yicha tekshirilsin'),
 ('278-4', 'XX-1', 'Kompyuter axborotini qonunga xilof ravishda o''zgartirish',       'medium', 'lex.uz bo''yicha tekshirilsin'),
 ('278-5', 'XX-1', 'Axborotdan foydalanish qoidalarini buzish',                       'low',    'lex.uz bo''yicha tekshirilsin'),
 ('278-6', 'XX-1', 'Axborot resurslariga noqonuniy ta''sir ko''rsatish',              'medium', 'lex.uz bo''yicha tekshirilsin'),
 ('278-7', 'XX-1', 'Axborot texnologiyalari sohasidagi boshqa qilmishlar',            'low',    'lex.uz bo''yicha tekshirilsin'),
 ('168',   'XI',   'Firibgarlik (axborot texnologiyalaridan foydalanib sodir etilgan)','high',  'og''irlashtiruvchi holat sifatida qo''llaniladi'),
 ('169',   'XI',   'O''g''irlik (bank plastik kartasi mablag''larini talon-toroj qilish)', 'high', 'kiberjinoyatlarning 98% shu toifada'),
 ('165',   'XI',   'Tovlamachilik',                                                    'high',   'sextortion / ransomware holatlari'),
 ('141',   'VII',  'Shaxsning shaxsiy hayotiga oid sirlarni oshkor qilish',            'medium', 'ma''lumot sizib chiqishi holatlari')
ON CONFLICT (code) DO NOTHING;

INSERT INTO detectors (kind, name, version, params) VALUES
 ('rule',      'brand_typosquat_uz', '1.0', '{"weight": 35}'),
 ('rule',      'suspicious_url_lexical', '1.0', '{"weight": 20}'),
 ('rule',      'fresh_domain', '1.0', '{"weight": 15}'),
 ('rule',      'fraud_keywords_uz', '1.0', '{"weight": 25}'),
 ('model',     'url_phish_gbdt', '0.1', '{"threshold": 0.5}'),
 ('heuristic', 'homoglyph_idn', '1.0', '{"weight": 30}')
ON CONFLICT (name, version) DO NOTHING;
