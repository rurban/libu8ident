/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */
/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   Generated by mkc26, do not modify.
   UNICODE version 14.0
   Filtered XID_Start/Continue with allowed scripts, safe IDTypes and NFC
*/

struct sc_c26 {
    uint32_t from;
    uint32_t to;
    enum u8id_sc sc;
    enum u8id_gc gc;
    // maxsize: Beng Deva Dogr Gong Gonm Gran Gujr Guru Knda Limb
    //          Mahj Mlym Nand Orya Sind Sinh Sylo Takr Taml Telu Tirh
    const char *scx;
};

// Filtering allowed scripts, XID_Start, Skipped Ids, !MEDIAL and NFC.
// Ranges split on GC and SCX changes
#ifndef EXTERN_SCRIPTS
const struct sc_c26 safec26_start_list[] = {
    {'$', '$', SC_Latin, GC_Sc, NULL},
    {'A', 'Z', SC_Latin, GC_Lu, NULL},
    {'_', '_', SC_Latin, GC_Pc, NULL},
    {'a', 'z', SC_Latin, GC_Ll, NULL},
    {0xC0, 0xD6, SC_Latin, GC_Lu, NULL}, //  À..Ö
    {0xD8, 0xF6, SC_Latin, GC_L, NULL}, //  Ø..ö
    {0xF8, 0x131, SC_Latin, GC_L, NULL}, //  ø..ı
    {0x134, 0x13E, SC_Latin, GC_L, NULL}, //  Ĵ..ľ
    {0x141, 0x148, SC_Latin, GC_L, NULL}, //  Ł..ň
    {0x14A, 0x17E, SC_Latin, GC_L, NULL}, //  Ŋ..ž
    {0x180, 0x180, SC_Latin, GC_Ll, NULL}, //  ƀ
    {0x18F, 0x18F, SC_Latin, GC_Lu, NULL}, //  Ə
    {0x1A0, 0x1A1, SC_Latin, GC_L, NULL}, //  Ơ..ơ
    {0x1AF, 0x1B0, SC_Latin, GC_L, NULL}, //  Ư..ư
    {0x1CD, 0x1DC, SC_Latin, GC_L, NULL}, //  Ǎ..ǜ
    {0x1DE, 0x1E3, SC_Latin, GC_L, NULL}, //  Ǟ..ǣ
    {0x1E6, 0x1F0, SC_Latin, GC_L, NULL}, //  Ǧ..ǰ
    {0x1F4, 0x1F5, SC_Latin, GC_L, NULL}, //  Ǵ..ǵ
    {0x1F8, 0x21B, SC_Latin, GC_L, NULL}, //  Ǹ..ț
    {0x21E, 0x21F, SC_Latin, GC_L, NULL}, //  Ȟ..ȟ
    {0x226, 0x236, SC_Latin, GC_L, NULL}, //  Ȧ..ȶ
    {0x250, 0x252, SC_Latin, GC_Ll, NULL}, //  ɐ..ɒ
    {0x255, 0x255, SC_Latin, GC_Ll, NULL}, //  ɕ
    {0x258, 0x25A, SC_Latin, GC_Ll, NULL}, //  ɘ..ɚ
    {0x25C, 0x262, SC_Latin, GC_Ll, NULL}, //  ɜ..ɢ
    {0x264, 0x267, SC_Latin, GC_Ll, NULL}, //  ɤ..ɧ
    {0x26A, 0x271, SC_Latin, GC_Ll, NULL}, //  ɪ..ɱ
    {0x273, 0x276, SC_Latin, GC_Ll, NULL}, //  ɳ..ɶ
    {0x278, 0x27B, SC_Latin, GC_Ll, NULL}, //  ɸ..ɻ
    {0x27D, 0x288, SC_Latin, GC_Ll, NULL}, //  ɽ..ʈ
    {0x28A, 0x291, SC_Latin, GC_Ll, NULL}, //  ʊ..ʑ
    {0x293, 0x29D, SC_Latin, GC_L, NULL}, //  ʓ..ʝ
    {0x29F, 0x2AF, SC_Latin, GC_Ll, NULL}, //  ʟ..ʯ
    {0x2B9, 0x2C1, SC_Common, GC_Lm, NULL}, //  ʹ..ˁ
    {0x2C6, 0x2D1, SC_Common, GC_Lm, NULL}, //  ˆ..ˑ
    {0x2EC, 0x2EC, SC_Common, GC_Lm, NULL}, //  ˬ
    {0x2EE, 0x2EE, SC_Common, GC_Lm, NULL}, //  ˮ
    {0x37B, 0x37D, SC_Greek, GC_Ll, NULL}, //  ͻ..ͽ
    {0x386, 0x386, SC_Greek, GC_Lu, NULL}, //  Ά
    {0x388, 0x38A, SC_Greek, GC_Lu, NULL}, //  Έ..Ί
    {0x38C, 0x38C, SC_Greek, GC_Lu, NULL}, //  Ό
    {0x38E, 0x3A1, SC_Greek, GC_L, NULL}, //  Ύ..Ρ
    {0x3A3, 0x3CF, SC_Greek, GC_L, NULL}, //  Σ..Ϗ
    {0x3D7, 0x3D7, SC_Greek, GC_Ll, NULL}, //  ϗ
    {0x3FC, 0x3FF, SC_Greek, GC_L, NULL}, //  ϼ..Ͽ
    {0x401, 0x45F, SC_Cyrillic, GC_L, NULL}, //  Ё..џ
    {0x48A, 0x4FF, SC_Cyrillic, GC_L, NULL}, //  Ҋ..ӿ
    {0x510, 0x529, SC_Cyrillic, GC_L, NULL}, //  Ԑ..ԩ
    {0x52E, 0x52F, SC_Cyrillic, GC_L, NULL}, //  Ԯ..ԯ
    {0x531, 0x556, SC_Armenian, GC_Lu, NULL}, //  Ա..Ֆ
    {0x559, 0x559, SC_Armenian, GC_Lm, NULL}, //  ՙ
    {0x560, 0x586, SC_Armenian, GC_Ll, NULL}, //  ՠ..ֆ
    {0x588, 0x588, SC_Armenian, GC_Ll, NULL}, //  ֈ
    {0x5D0, 0x5EA, SC_Hebrew, GC_Lo, NULL}, //  א..ת
    {0x5EF, 0x5F2, SC_Hebrew, GC_Lo, NULL}, //  ׯ..ײ
    {0x620, 0x63F, SC_Arabic, GC_Lo, NULL}, //  ؠ..ؿ
    {0x641, 0x64A, SC_Arabic, GC_Lo, NULL}, //  ف..ي
    {0x671, 0x672, SC_Arabic, GC_Lo, NULL}, //  ٱ..ٲ
    {0x674, 0x674, SC_Arabic, GC_Lo, NULL}, //  ٴ
    {0x679, 0x68D, SC_Arabic, GC_Lo, NULL}, //  ٹ..ڍ
    {0x68F, 0x6A0, SC_Arabic, GC_Lo, NULL}, //  ڏ..ڠ
    {0x6A2, 0x6D3, SC_Arabic, GC_Lo, NULL}, //  ڢ..ۓ
    {0x6D5, 0x6D5, SC_Arabic, GC_Lo, NULL}, //  ە
    {0x6E5, 0x6E6, SC_Arabic, GC_Lm, NULL}, //  ۥ..ۦ
    {0x6EE, 0x6EF, SC_Arabic, GC_Lo, NULL}, //  ۮ..ۯ
    {0x6FA, 0x6FC, SC_Arabic, GC_Lo, NULL}, //  ۺ..ۼ
    {0x6FF, 0x6FF, SC_Arabic, GC_Lo, NULL}, //  ۿ
    {0x750, 0x77F, SC_Arabic, GC_Lo, NULL}, //  ݐ..ݿ
    {0x781, 0x7A5, SC_Thaana, GC_Lo, NULL}, //  ށ..ޥ
    {0x7B1, 0x7B1, SC_Thaana, GC_Lo, NULL}, //  ޱ
    {0x870, 0x887, SC_Arabic, GC_Lo, NULL}, //  ࡰ..ࢇ
    {0x889, 0x88E, SC_Arabic, GC_Lo, NULL}, //  ࢉ..ࢎ
    {0x8A0, 0x8AC, SC_Arabic, GC_Lo, NULL}, //  ࢠ..ࢬ
    {0x8B2, 0x8B2, SC_Arabic, GC_Lo, NULL}, //  ࢲ
    {0x8B5, 0x8C9, SC_Arabic, GC_L, NULL}, //  ࢵ..ࣉ
    {0x904, 0x939, SC_Devanagari, GC_Lo, NULL}, //  ऄ..ह
    {0x93D, 0x93D, SC_Devanagari, GC_Lo, NULL}, //  ऽ
    {0x950, 0x950, SC_Devanagari, GC_Lo, NULL}, //  ॐ
    {0x960, 0x961, SC_Devanagari, GC_Lo, NULL}, //  ॠ..ॡ
    {0x971, 0x977, SC_Devanagari, GC_L, NULL}, //  ॱ..ॷ
    {0x979, 0x97F, SC_Devanagari, GC_Lo, NULL}, //  ॹ..ॿ
    {0x985, 0x98C, SC_Bengali, GC_Lo, NULL}, //  অ..ঌ
    {0x98F, 0x990, SC_Bengali, GC_Lo, NULL}, //  এ..ঐ
    {0x993, 0x9A8, SC_Bengali, GC_Lo, NULL}, //  ও..ন
    {0x9AA, 0x9B0, SC_Bengali, GC_Lo, NULL}, //  প..র
    {0x9B2, 0x9B2, SC_Bengali, GC_Lo, NULL}, //  ল
    {0x9B6, 0x9B9, SC_Bengali, GC_Lo, NULL}, //  শ..হ
    {0x9BD, 0x9BD, SC_Bengali, GC_Lo, NULL}, //  ঽ
    {0x9CE, 0x9CE, SC_Bengali, GC_Lo, NULL}, //  ৎ
    {0x9E0, 0x9E1, SC_Bengali, GC_Lo, NULL}, //  ৠ..ৡ
    {0x9F0, 0x9F1, SC_Bengali, GC_Lo, NULL}, //  ৰ..ৱ
    {0xA05, 0xA0A, SC_Gurmukhi, GC_Lo, NULL}, //  ਅ..ਊ
    {0xA0F, 0xA10, SC_Gurmukhi, GC_Lo, NULL}, //  ਏ..ਐ
    {0xA13, 0xA28, SC_Gurmukhi, GC_Lo, NULL}, //  ਓ..ਨ
    {0xA2A, 0xA30, SC_Gurmukhi, GC_Lo, NULL}, //  ਪ..ਰ
    {0xA32, 0xA32, SC_Gurmukhi, GC_Lo, NULL}, //  ਲ
    {0xA35, 0xA35, SC_Gurmukhi, GC_Lo, NULL}, //  ਵ
    {0xA38, 0xA39, SC_Gurmukhi, GC_Lo, NULL}, //  ਸ..ਹ
    {0xA5C, 0xA5C, SC_Gurmukhi, GC_Lo, NULL}, //  ੜ
    {0xA72, 0xA74, SC_Gurmukhi, GC_Lo, NULL}, //  ੲ..ੴ
    {0xA85, 0xA8D, SC_Gujarati, GC_Lo, NULL}, //  અ..ઍ
    {0xA8F, 0xA91, SC_Gujarati, GC_Lo, NULL}, //  એ..ઑ
    {0xA93, 0xAA8, SC_Gujarati, GC_Lo, NULL}, //  ઓ..ન
    {0xAAA, 0xAB0, SC_Gujarati, GC_Lo, NULL}, //  પ..ર
    {0xAB2, 0xAB3, SC_Gujarati, GC_Lo, NULL}, //  લ..ળ
    {0xAB5, 0xAB9, SC_Gujarati, GC_Lo, NULL}, //  વ..હ
    {0xABD, 0xABD, SC_Gujarati, GC_Lo, NULL}, //  ઽ
    {0xAD0, 0xAD0, SC_Gujarati, GC_Lo, NULL}, //  ૐ
    {0xAE0, 0xAE1, SC_Gujarati, GC_Lo, NULL}, //  ૠ..ૡ
    {0xB05, 0xB0C, SC_Oriya, GC_Lo, NULL}, //  ଅ..ଌ
    {0xB0F, 0xB10, SC_Oriya, GC_Lo, NULL}, //  ଏ..ଐ
    {0xB13, 0xB28, SC_Oriya, GC_Lo, NULL}, //  ଓ..ନ
    {0xB2A, 0xB30, SC_Oriya, GC_Lo, NULL}, //  ପ..ର
    {0xB32, 0xB33, SC_Oriya, GC_Lo, NULL}, //  ଲ..ଳ
    {0xB35, 0xB39, SC_Oriya, GC_Lo, NULL}, //  ଵ..ହ
    {0xB3D, 0xB3D, SC_Oriya, GC_Lo, NULL}, //  ଽ
    {0xB5F, 0xB61, SC_Oriya, GC_Lo, NULL}, //  ୟ..ୡ
    {0xB71, 0xB71, SC_Oriya, GC_Lo, NULL}, //  ୱ
    {0xB83, 0xB83, SC_Tamil, GC_Lo, NULL}, //  ஃ
    {0xB85, 0xB8A, SC_Tamil, GC_Lo, NULL}, //  அ..ஊ
    {0xB8E, 0xB90, SC_Tamil, GC_Lo, NULL}, //  எ..ஐ
    {0xB92, 0xB95, SC_Tamil, GC_Lo, NULL}, //  ஒ..க
    {0xB99, 0xB9A, SC_Tamil, GC_Lo, NULL}, //  ங..ச
    {0xB9C, 0xB9C, SC_Tamil, GC_Lo, NULL}, //  ஜ
    {0xB9E, 0xB9F, SC_Tamil, GC_Lo, NULL}, //  ஞ..ட
    {0xBA3, 0xBA4, SC_Tamil, GC_Lo, NULL}, //  ண..த
    {0xBA8, 0xBAA, SC_Tamil, GC_Lo, NULL}, //  ந..ப
    {0xBAE, 0xBB9, SC_Tamil, GC_Lo, NULL}, //  ம..ஹ
    {0xBD0, 0xBD0, SC_Tamil, GC_Lo, NULL}, //  ௐ
    {0xC05, 0xC0C, SC_Telugu, GC_Lo, NULL}, //  అ..ఌ
    {0xC0E, 0xC10, SC_Telugu, GC_Lo, NULL}, //  ఎ..ఐ
    {0xC12, 0xC28, SC_Telugu, GC_Lo, NULL}, //  ఒ..న
    {0xC2A, 0xC33, SC_Telugu, GC_Lo, NULL}, //  ప..ళ
    {0xC35, 0xC39, SC_Telugu, GC_Lo, NULL}, //  వ..హ
    {0xC3D, 0xC3D, SC_Telugu, GC_Lo, NULL}, //  ఽ
    {0xC5D, 0xC5D, SC_Telugu, GC_Lo, NULL}, //  ౝ
    {0xC60, 0xC61, SC_Telugu, GC_Lo, NULL}, //  ౠ..ౡ
    {0xC80, 0xC80, SC_Kannada, GC_Lo, NULL}, //  ಀ
    {0xC85, 0xC8C, SC_Kannada, GC_Lo, NULL}, //  ಅ..ಌ
    {0xC8E, 0xC90, SC_Kannada, GC_Lo, NULL}, //  ಎ..ಐ
    {0xC92, 0xCA8, SC_Kannada, GC_Lo, NULL}, //  ಒ..ನ
    {0xCAA, 0xCB3, SC_Kannada, GC_Lo, NULL}, //  ಪ..ಳ
    {0xCB5, 0xCB9, SC_Kannada, GC_Lo, NULL}, //  ವ..ಹ
    {0xCBD, 0xCBD, SC_Kannada, GC_Lo, NULL}, //  ಽ
    {0xCDD, 0xCDD, SC_Kannada, GC_Lo, NULL}, //  ೝ
    {0xCE0, 0xCE1, SC_Kannada, GC_Lo, NULL}, //  ೠ..ೡ
    {0xCF1, 0xCF2, SC_Kannada, GC_Lo, NULL}, //  ೱ..ೲ
    {0xD05, 0xD0C, SC_Malayalam, GC_Lo, NULL}, //  അ..ഌ
    {0xD0E, 0xD10, SC_Malayalam, GC_Lo, NULL}, //  എ..ഐ
    {0xD12, 0xD3A, SC_Malayalam, GC_Lo, NULL}, //  ഒ..ഺ
    {0xD3D, 0xD3D, SC_Malayalam, GC_Lo, NULL}, //  ഽ
    {0xD4E, 0xD4E, SC_Malayalam, GC_Lo, NULL}, //  ൎ
    {0xD54, 0xD56, SC_Malayalam, GC_Lo, NULL}, //  ൔ..ൖ
    {0xD60, 0xD61, SC_Malayalam, GC_Lo, NULL}, //  ൠ..ൡ
    {0xD7A, 0xD7F, SC_Malayalam, GC_Lo, NULL}, //  ൺ..ൿ
    {0xD85, 0xD8E, SC_Sinhala, GC_Lo, NULL}, //  අ..ඎ
    {0xD91, 0xD96, SC_Sinhala, GC_Lo, NULL}, //  එ..ඖ
    {0xD9A, 0xDA5, SC_Sinhala, GC_Lo, NULL}, //  ක..ඥ
    {0xDA7, 0xDB1, SC_Sinhala, GC_Lo, NULL}, //  ට..න
    {0xDB3, 0xDBB, SC_Sinhala, GC_Lo, NULL}, //  ඳ..ර
    {0xDBD, 0xDBD, SC_Sinhala, GC_Lo, NULL}, //  ල
    {0xDC0, 0xDC6, SC_Sinhala, GC_Lo, NULL}, //  ව..ෆ
    {0xE01, 0xE30, SC_Thai, GC_Lo, NULL}, //  ก..ะ
    {0xE32, 0xE32, SC_Thai, GC_Lo, NULL}, //  า
    {0xE40, 0xE46, SC_Thai, GC_L, NULL}, //  เ..ๆ
    {0xE81, 0xE82, SC_Lao, GC_Lo, NULL}, //  ກ..ຂ
    {0xE84, 0xE84, SC_Lao, GC_Lo, NULL}, //  ຄ
    {0xE86, 0xE8A, SC_Lao, GC_Lo, NULL}, //  ຆ..ຊ
    {0xE8C, 0xEA3, SC_Lao, GC_Lo, NULL}, //  ຌ..ຣ
    {0xEA5, 0xEA5, SC_Lao, GC_Lo, NULL}, //  ລ
    {0xEA7, 0xEB0, SC_Lao, GC_Lo, NULL}, //  ວ..ະ
    {0xEB2, 0xEB2, SC_Lao, GC_Lo, NULL}, //  າ
    {0xEBD, 0xEBD, SC_Lao, GC_Lo, NULL}, //  ຽ
    {0xEC0, 0xEC4, SC_Lao, GC_Lo, NULL}, //  ເ..ໄ
    {0xEC6, 0xEC6, SC_Lao, GC_Lm, NULL}, //  ໆ
    {0xEDE, 0xEDF, SC_Lao, GC_Lo, NULL}, //  ໞ..ໟ
    {0xF00, 0xF00, SC_Tibetan, GC_Lo, NULL}, //  ༀ
    {0xF40, 0xF42, SC_Tibetan, GC_Lo, NULL}, //  ཀ..ག
    {0xF44, 0xF47, SC_Tibetan, GC_Lo, NULL}, //  ང..ཇ
    {0xF49, 0xF4C, SC_Tibetan, GC_Lo, NULL}, //  ཉ..ཌ
    {0xF4E, 0xF51, SC_Tibetan, GC_Lo, NULL}, //  ཎ..ད
    {0xF53, 0xF56, SC_Tibetan, GC_Lo, NULL}, //  ན..བ
    {0xF58, 0xF5B, SC_Tibetan, GC_Lo, NULL}, //  མ..ཛ
    {0xF5D, 0xF68, SC_Tibetan, GC_Lo, NULL}, //  ཝ..ཨ
    {0xF6A, 0xF6C, SC_Tibetan, GC_Lo, NULL}, //  ཪ..ཬ
    {0xF88, 0xF8C, SC_Tibetan, GC_Lo, NULL}, //  ྈ..ྌ
    {0x1000, 0x102A, SC_Myanmar, GC_Lo, NULL}, //  က..ဪ
    {0x103F, 0x103F, SC_Myanmar, GC_Lo, NULL}, //  ဿ
    {0x1050, 0x1055, SC_Myanmar, GC_Lo, NULL}, //  ၐ..ၕ
    {0x105A, 0x105D, SC_Myanmar, GC_Lo, NULL}, //  ၚ..ၝ
    {0x1061, 0x1061, SC_Myanmar, GC_Lo, NULL}, //  ၡ
    {0x1065, 0x1066, SC_Myanmar, GC_Lo, NULL}, //  ၥ..ၦ
    {0x106E, 0x1070, SC_Myanmar, GC_Lo, NULL}, //  ၮ..ၰ
    {0x1075, 0x1081, SC_Myanmar, GC_Lo, NULL}, //  ၵ..ႁ
    {0x108E, 0x108E, SC_Myanmar, GC_Lo, NULL}, //  ႎ
    {0x10C7, 0x10C7, SC_Georgian, GC_Lu, NULL}, //  Ⴧ
    {0x10CD, 0x10CD, SC_Georgian, GC_Lu, NULL}, //  Ⴭ
    {0x10D0, 0x10F0, SC_Georgian, GC_Ll, NULL}, //  ა..ჰ
    {0x10F7, 0x10FA, SC_Georgian, GC_Ll, NULL}, //  ჷ..ჺ
    {0x10FD, 0x10FF, SC_Georgian, GC_Ll, NULL}, //  ჽ..ჿ
    {0x1200, 0x1248, SC_Ethiopic, GC_Lo, NULL}, //  ሀ..ቈ
    {0x124A, 0x124D, SC_Ethiopic, GC_Lo, NULL}, //  ቊ..ቍ
    {0x1250, 0x1256, SC_Ethiopic, GC_Lo, NULL}, //  ቐ..ቖ
    {0x1258, 0x1258, SC_Ethiopic, GC_Lo, NULL}, //  ቘ
    {0x125A, 0x125D, SC_Ethiopic, GC_Lo, NULL}, //  ቚ..ቝ
    {0x1260, 0x1288, SC_Ethiopic, GC_Lo, NULL}, //  በ..ኈ
    {0x128A, 0x128D, SC_Ethiopic, GC_Lo, NULL}, //  ኊ..ኍ
    {0x1290, 0x12B0, SC_Ethiopic, GC_Lo, NULL}, //  ነ..ኰ
    {0x12B2, 0x12B5, SC_Ethiopic, GC_Lo, NULL}, //  ኲ..ኵ
    {0x12B8, 0x12BE, SC_Ethiopic, GC_Lo, NULL}, //  ኸ..ኾ
    {0x12C0, 0x12C0, SC_Ethiopic, GC_Lo, NULL}, //  ዀ
    {0x12C2, 0x12C5, SC_Ethiopic, GC_Lo, NULL}, //  ዂ..ዅ
    {0x12C8, 0x12D6, SC_Ethiopic, GC_Lo, NULL}, //  ወ..ዖ
    {0x12D8, 0x1310, SC_Ethiopic, GC_Lo, NULL}, //  ዘ..ጐ
    {0x1312, 0x1315, SC_Ethiopic, GC_Lo, NULL}, //  ጒ..ጕ
    {0x1318, 0x135A, SC_Ethiopic, GC_Lo, NULL}, //  ጘ..ፚ
    {0x1380, 0x138F, SC_Ethiopic, GC_Lo, NULL}, //  ᎀ..ᎏ
    {0x1780, 0x17A2, SC_Khmer, GC_Lo, NULL}, //  ក..អ
    {0x17A5, 0x17A7, SC_Khmer, GC_Lo, NULL}, //  ឥ..ឧ
    {0x17A9, 0x17B3, SC_Khmer, GC_Lo, NULL}, //  ឩ..ឳ
    {0x17D7, 0x17D7, SC_Khmer, GC_Lm, NULL}, //  ៗ
    {0x17DC, 0x17DC, SC_Khmer, GC_Lo, NULL}, //  ៜ
    {0x1C90, 0x1CBA, SC_Georgian, GC_Lu, NULL}, //  Ა..Ჺ
    {0x1CBD, 0x1CBF, SC_Georgian, GC_Lu, NULL}, //  Ჽ..Ჿ
    {0x1D00, 0x1D25, SC_Latin, GC_Ll, NULL}, //  ᴀ..ᴥ
    {0x1D27, 0x1D2A, SC_Greek, GC_Ll, NULL}, //  ᴧ..ᴪ
    {0x1D2F, 0x1D2F, SC_Latin, GC_Lm, NULL}, //  ᴯ
    {0x1D3B, 0x1D3B, SC_Latin, GC_Lm, NULL}, //  ᴻ
    {0x1D4E, 0x1D4E, SC_Latin, GC_Lm, NULL}, //  ᵎ
    {0x1D6B, 0x1D77, SC_Latin, GC_Ll, NULL}, //  ᵫ..ᵷ
    {0x1D79, 0x1D9A, SC_Latin, GC_Ll, NULL}, //  ᵹ..ᶚ
    {0x1E00, 0x1E99, SC_Latin, GC_L, NULL}, //  Ḁ..ẙ
    {0x1E9C, 0x1EFF, SC_Latin, GC_L, NULL}, //  ẜ..ỿ
    {0x1F01, 0x1F15, SC_Greek, GC_L, NULL}, //  ἁ..ἕ
    {0x1F18, 0x1F1D, SC_Greek, GC_Lu, NULL}, //  Ἐ..Ἕ
    {0x1F20, 0x1F45, SC_Greek, GC_L, NULL}, //  ἠ..ὅ
    {0x1F48, 0x1F4D, SC_Greek, GC_Lu, NULL}, //  Ὀ..Ὅ
    {0x1F50, 0x1F57, SC_Greek, GC_Ll, NULL}, //  ὐ..ὗ
    {0x1F59, 0x1F59, SC_Greek, GC_Lu, NULL}, //  Ὑ
    {0x1F5B, 0x1F5B, SC_Greek, GC_Lu, NULL}, //  Ὓ
    {0x1F5D, 0x1F5D, SC_Greek, GC_Lu, NULL}, //  Ὕ
    {0x1F5F, 0x1F70, SC_Greek, GC_L, NULL}, //  Ὗ..ὰ
    {0x1F72, 0x1F72, SC_Greek, GC_Ll, NULL}, //  ὲ
    {0x1F74, 0x1F74, SC_Greek, GC_Ll, NULL}, //  ὴ
    {0x1F76, 0x1F76, SC_Greek, GC_Ll, NULL}, //  ὶ
    {0x1F78, 0x1F78, SC_Greek, GC_Ll, NULL}, //  ὸ
    {0x1F7A, 0x1F7A, SC_Greek, GC_Ll, NULL}, //  ὺ
    {0x1F7C, 0x1F7C, SC_Greek, GC_Ll, NULL}, //  ὼ
    {0x1F80, 0x1FB4, SC_Greek, GC_L, NULL}, //  ᾀ..ᾴ
    {0x1FB6, 0x1FBA, SC_Greek, GC_L, NULL}, //  ᾶ..Ὰ
    {0x1FBC, 0x1FBC, SC_Greek, GC_Lt, NULL}, //  ᾼ
    {0x1FC2, 0x1FC4, SC_Greek, GC_Ll, NULL}, //  ῂ..ῄ
    {0x1FC6, 0x1FC8, SC_Greek, GC_L, NULL}, //  ῆ..Ὲ
    {0x1FCA, 0x1FCA, SC_Greek, GC_Lu, NULL}, //  Ὴ
    {0x1FCC, 0x1FCC, SC_Greek, GC_Lt, NULL}, //  ῌ
    {0x1FD0, 0x1FD2, SC_Greek, GC_Ll, NULL}, //  ῐ..ῒ
    {0x1FD6, 0x1FDA, SC_Greek, GC_L, NULL}, //  ῖ..Ὶ
    {0x1FE0, 0x1FE2, SC_Greek, GC_Ll, NULL}, //  ῠ..ῢ
    {0x1FE4, 0x1FEA, SC_Greek, GC_L, NULL}, //  ῤ..Ὺ
    {0x1FEC, 0x1FEC, SC_Greek, GC_Lu, NULL}, //  Ῥ
    {0x1FF2, 0x1FF4, SC_Greek, GC_Ll, NULL}, //  ῲ..ῴ
    {0x1FF6, 0x1FF8, SC_Greek, GC_L, NULL}, //  ῶ..Ὸ
    {0x1FFA, 0x1FFA, SC_Greek, GC_Lu, NULL}, //  Ὼ
    {0x1FFC, 0x1FFC, SC_Greek, GC_Lt, NULL}, //  ῼ
    {0x2118, 0x2118, SC_Common, GC_Sm, NULL}, //  ℘
    {0x212E, 0x212E, SC_Common, GC_So, NULL}, //  ℮
    {0x2C60, 0x2C67, SC_Latin, GC_L, NULL}, //  Ⱡ..Ⱨ
    {0x2C77, 0x2C7B, SC_Latin, GC_Ll, NULL}, //  ⱷ..ⱻ
    {0x2D27, 0x2D27, SC_Georgian, GC_Ll, NULL}, //  ⴧ
    {0x2D2D, 0x2D2D, SC_Georgian, GC_Ll, NULL}, //  ⴭ
    {0x2D80, 0x2D96, SC_Ethiopic, GC_Lo, NULL}, //  ⶀ..ⶖ
    {0x2DA0, 0x2DA6, SC_Ethiopic, GC_Lo, NULL}, //  ⶠ..ⶦ
    {0x2DA8, 0x2DAE, SC_Ethiopic, GC_Lo, NULL}, //  ⶨ..ⶮ
    {0x2DB0, 0x2DB6, SC_Ethiopic, GC_Lo, NULL}, //  ⶰ..ⶶ
    {0x2DB8, 0x2DBE, SC_Ethiopic, GC_Lo, NULL}, //  ⶸ..ⶾ
    {0x2DC0, 0x2DC6, SC_Ethiopic, GC_Lo, NULL}, //  ⷀ..ⷆ
    {0x2DC8, 0x2DCE, SC_Ethiopic, GC_Lo, NULL}, //  ⷈ..ⷎ
    {0x2DD0, 0x2DD6, SC_Ethiopic, GC_Lo, NULL}, //  ⷐ..ⷖ
    {0x2DD8, 0x2DDE, SC_Ethiopic, GC_Lo, NULL}, //  ⷘ..ⷞ
    {0x3005, 0x3005, SC_Han, GC_Lm, NULL}, //  々
    {0x3007, 0x3007, SC_Han, GC_Nl, NULL}, //  〇
    {0x3021, 0x3029, SC_Han, GC_Nl, NULL}, //  〡..〩
    {0x3031, 0x3035, SC_Common, GC_Lm, "\x11\x12"}, //Hiragana,Katakana //  〱..〵
    {0x303B, 0x303B, SC_Han, GC_Lm, NULL}, //  〻
    {0x3041, 0x3096, SC_Hiragana, GC_Lo, NULL}, //  ぁ..ゖ
    {0x309D, 0x309E, SC_Hiragana, GC_Lm, NULL}, //  ゝ..ゞ
    {0x30A1, 0x30FA, SC_Katakana, GC_Lo, NULL}, //  ァ..ヺ
    {0x30FC, 0x30FC, SC_Common, GC_Lm, "\x11\x12"}, //Hiragana,Katakana //  ー
    {0x30FE, 0x30FE, SC_Katakana, GC_Lm, NULL}, //  ヾ
    {0x3105, 0x312D, SC_Bopomofo, GC_Lo, NULL}, //  ㄅ..ㄭ
    {0x312F, 0x312F, SC_Bopomofo, GC_Lo, NULL}, //  ㄯ
    {0x31A0, 0x31BF, SC_Bopomofo, GC_Lo, NULL}, //  ㆠ..ㆿ
    {0x3400, 0x4DBF, SC_Han, GC_Lo, NULL}, //  㐀..䶿
    {0x4E00, 0x9FFF, SC_Han, GC_Lo, NULL}, //  一..鿿
    {0xA67F, 0xA67F, SC_Cyrillic, GC_Lm, NULL}, //  ꙿ
    {0xA717, 0xA71F, SC_Common, GC_Lm, NULL}, //  ꜗ..ꜟ
    {0xA788, 0xA788, SC_Common, GC_Lm, NULL}, //  ꞈ
    {0xA78D, 0xA78E, SC_Latin, GC_L, NULL}, //  Ɥ..ꞎ
    {0xA792, 0xA793, SC_Latin, GC_L, NULL}, //  Ꞓ..ꞓ
    {0xA7AA, 0xA7AA, SC_Latin, GC_Lu, NULL}, //  Ɦ
    {0xA7AE, 0xA7AF, SC_Latin, GC_L, NULL}, //  Ɪ..ꞯ
    {0xA7B8, 0xA7CA, SC_Latin, GC_L, NULL}, //  Ꞹ..ꟊ
    {0xA7D0, 0xA7D1, SC_Latin, GC_L, NULL}, //  Ꟑ..ꟑ
    {0xA7D3, 0xA7D3, SC_Latin, GC_Ll, NULL}, //  ꟓ
    {0xA7D5, 0xA7D9, SC_Latin, GC_L, NULL}, //  ꟕ..ꟙ
    {0xA7FA, 0xA7FA, SC_Latin, GC_Ll, NULL}, //  ꟺ
    {0xA9E7, 0xA9EF, SC_Myanmar, GC_Lo, NULL}, //  ꧧ..ꧯ
    {0xA9FA, 0xA9FE, SC_Myanmar, GC_Lo, NULL}, //  ꧺ..ꧾ
    {0xAA60, 0xAA76, SC_Myanmar, GC_L, NULL}, //  ꩠ..ꩶ
    {0xAA7A, 0xAA7A, SC_Myanmar, GC_Lo, NULL}, //  ꩺ
    {0xAA7E, 0xAA7F, SC_Myanmar, GC_Lo, NULL}, //  ꩾ..ꩿ
    {0xAB01, 0xAB06, SC_Ethiopic, GC_Lo, NULL}, //  ꬁ..ꬆ
    {0xAB09, 0xAB0E, SC_Ethiopic, GC_Lo, NULL}, //  ꬉ..ꬎ
    {0xAB11, 0xAB16, SC_Ethiopic, GC_Lo, NULL}, //  ꬑ..ꬖ
    {0xAB20, 0xAB26, SC_Ethiopic, GC_Lo, NULL}, //  ꬠ..ꬦ
    {0xAB28, 0xAB2E, SC_Ethiopic, GC_Lo, NULL}, //  ꬨ..ꬮ
    {0xAB66, 0xAB68, SC_Latin, GC_Ll, NULL}, //  ꭦ..ꭨ
    {0xFA0E, 0xFA0F, SC_Han, GC_Lo, NULL}, //  﨎..﨏
    {0xFA11, 0xFA11, SC_Han, GC_Lo, NULL}, //  﨑
    {0xFA13, 0xFA14, SC_Han, GC_Lo, NULL}, //  﨓..﨔
    {0xFA1F, 0xFA1F, SC_Han, GC_Lo, NULL}, //  﨟
    {0xFA21, 0xFA21, SC_Han, GC_Lo, NULL}, //  﨡
    {0xFA23, 0xFA24, SC_Han, GC_Lo, NULL}, //  﨣..﨤
    {0xFA27, 0xFA29, SC_Han, GC_Lo, NULL}, //  﨧..﨩
    {0x1B11F, 0x1B11F, SC_Hiragana, GC_Lo, NULL}, //  𛄟
    {0x1B121, 0x1B122, SC_Katakana, GC_Lo, NULL}, //  𛄡..𛄢
    {0x1B150, 0x1B152, SC_Hiragana, GC_Lo, NULL}, //  𛅐..𛅒
    {0x1B164, 0x1B167, SC_Katakana, GC_Lo, NULL}, //  𛅤..𛅧
    {0x1DF00, 0x1DF1E, SC_Latin, GC_L, NULL}, //  𝼀..𝼞
    {0x1E7E0, 0x1E7E6, SC_Ethiopic, GC_Lo, NULL}, //  𞟠..𞟦
    {0x1E7E8, 0x1E7EB, SC_Ethiopic, GC_Lo, NULL}, //  𞟨..𞟫
    {0x1E7ED, 0x1E7EE, SC_Ethiopic, GC_Lo, NULL}, //  𞟭..𞟮
    {0x1E7F0, 0x1E7FE, SC_Ethiopic, GC_Lo, NULL}, //  𞟰..𞟾
    {0x20000, 0x2A6DF, SC_Han, GC_Lo, NULL}, //  𠀀..𪛟
    {0x2A700, 0x2B738, SC_Han, GC_Lo, NULL}, //  𪜀..𫜸
    {0x2B740, 0x2B81D, SC_Han, GC_Lo, NULL}, //  𫝀..𫠝
    {0x2B820, 0x2CEA1, SC_Han, GC_Lo, NULL}, //  𫠠..𬺡
    {0x2CEB0, 0x2EBE0, SC_Han, GC_Lo, NULL}, //  𬺰..𮯠
    {0x30000, 0x3134A, SC_Han, GC_Lo, NULL}, //  𰀀..𱍊
};
#else
extern const struct sc_c26 safec26_start_list[335];
#endif
// 243 ranges, 92 singles, 95986 codepoints

// Filtering allowed scripts, XID_Continue,!XID_Start, safe IDTypes, NFC
// MEDIAL from XID_Start and !MARK. Split on GC and SCX
#ifndef EXTERN_SCRIPTS
const struct sc_c26 safec26_cont_list[] = {
    {0x30, 0x39, SC_Common, GC_Nd, NULL}, //  0..9
    {0x5F, 0x5F, SC_Common, GC_Pc, NULL}, //  _
    {0x660, 0x669, SC_Arabic, GC_Nd, "\x03\x1c\x7d"}, //Arabic,Thaana,Yezidi //  ٠..٩
    {0x6F0, 0x6F9, SC_Arabic, GC_Nd, NULL}, //  ۰..۹
    {0x966, 0x96F, SC_Devanagari, GC_Nd, "\x08\x31\x3f\x48"}, //Devanagari,Dogra,Kaithi,Mahajani //  ०..९
    {0x9E6, 0x9EF, SC_Bengali, GC_Nd, "\x05\x84\x98"}, //Bengali,Chakma,Syloti_Nagri //  ০..৯
    {0xA66, 0xA6F, SC_Gurmukhi, GC_Nd, "\x0d\x54"}, //Gurmukhi,Multani //  ੦..੯
    {0xAE6, 0xAEF, SC_Gujarati, GC_Nd, "\x0c\x42"}, //Gujarati,Khojki //  ૦..૯
    {0xB66, 0xB6F, SC_Oriya, GC_Nd, NULL}, //  ୦..୯
    {0xBE6, 0xBEF, SC_Tamil, GC_Nd, "\x38\x1a"}, //Grantha,Tamil //  ௦..௯
    {0xC66, 0xC6F, SC_Telugu, GC_Nd, NULL}, //  ౦..౯
    {0xCE6, 0xCEF, SC_Kannada, GC_Nd, "\x13\x56"}, //Kannada,Nandinagari //  ೦..೯
    {0xD66, 0xD6F, SC_Malayalam, GC_Nd, NULL}, //  ൦..൯
    {0xE50, 0xE59, SC_Thai, GC_Nd, NULL}, //  ๐..๙
    {0xED0, 0xED9, SC_Lao, GC_Nd, NULL}, //  ໐..໙
    {0xF20, 0xF29, SC_Tibetan, GC_Nd, NULL}, //  ༠..༩
    {0x1040, 0x1049, SC_Myanmar, GC_Nd, "\x84\x17\x9a"}, //Chakma,Myanmar,Tai_Le //  ၀..၉
    {0x1090, 0x1099, SC_Myanmar, GC_Nd, NULL}, //  ႐..႙
    {0x17E0, 0x17E9, SC_Khmer, GC_Nd, NULL}, //  ០..៩
    {0x203F, 0x2040, SC_Common, GC_Pc, NULL}, //  ‿..⁀
    {0xA9F0, 0xA9F9, SC_Myanmar, GC_Nd, NULL}, //  ꧰..꧹
};
#else
extern const struct sc_c26 safec26_cont_list[21];
#endif
// 20 ranges, 1 singles, 172 codepoints


//---------------------------------------------------

// Only excluded scripts, XID_Start, more IDTypes, NFC, !MEDIAL and !MARK
#ifndef EXTERN_SCRIPTS
const struct sc_c26 safec26_excl_start_list[] = {
    {0x3E2, 0x3EF, SC_Coptic, GC_L, NULL}, //  (Excluded) Ϣ..ϯ
    {0x800, 0x815, SC_Samaritan, GC_Lo, NULL}, //  (Excluded) ࠀ..ࠕ
    {0x81A, 0x81A, SC_Samaritan, GC_Lm, NULL}, //  (Excluded) ࠚ
    {0x824, 0x824, SC_Samaritan, GC_Lm, NULL}, //  (Excluded) ࠤ
    {0x828, 0x828, SC_Samaritan, GC_Lm, NULL}, //  (Excluded) ࠨ
    {0x1681, 0x169A, SC_Ogham, GC_Lo, NULL}, //  (Excluded) ᚁ..ᚚ
    {0x16A0, 0x16EA, SC_Runic, GC_Lo, NULL}, //  (Excluded) ᚠ..ᛪ
    {0x16EE, 0x16F8, SC_Runic, GC_V, NULL}, //  (Excluded) ᛮ..ᛸ
    {0x1700, 0x1711, SC_Tagalog, GC_Lo, NULL}, //  (Excluded) ᜀ..ᜑ
    {0x171F, 0x171F, SC_Tagalog, GC_Lo, NULL}, //  (Excluded) ᜟ
    {0x1721, 0x1731, SC_Hanunoo, GC_Lo, NULL}, //  (Excluded) ᜡ..ᜱ
    {0x1740, 0x1751, SC_Buhid, GC_Lo, NULL}, //  (Excluded) ᝀ..ᝑ
    {0x1760, 0x176C, SC_Tagbanwa, GC_Lo, NULL}, //  (Excluded) ᝠ..ᝬ
    {0x176E, 0x1770, SC_Tagbanwa, GC_Lo, NULL}, //  (Excluded) ᝮ..ᝰ
    {0x1820, 0x1878, SC_Mongolian, GC_L, NULL}, //  (Excluded) ᠠ..ᡸ
    {0x1880, 0x1884, SC_Mongolian, GC_Lo, NULL}, //  (Excluded) ᢀ..ᢄ
    {0x1887, 0x18A8, SC_Mongolian, GC_Lo, NULL}, //  (Excluded) ᢇ..ᢨ
    {0x18AA, 0x18AA, SC_Mongolian, GC_Lo, NULL}, //  (Excluded) ᢪ
    {0x1A00, 0x1A16, SC_Buginese, GC_Lo, NULL}, //  (Excluded) ᨀ..ᨖ
    {0x2C00, 0x2C5F, SC_Glagolitic, GC_L, NULL}, //  (Excluded) Ⰰ..ⱟ
    {0x2C80, 0x2CE4, SC_Coptic, GC_L, NULL}, //  (Excluded) Ⲁ..ⳤ
    {0x2CEB, 0x2CEE, SC_Coptic, GC_L, NULL}, //  (Excluded) Ⳬ..ⳮ
    {0x2CF2, 0x2CF3, SC_Coptic, GC_L, NULL}, //  (Excluded) Ⳳ..ⳳ
    {0xA840, 0xA873, SC_Phags_Pa, GC_Lo, NULL}, //  (Excluded) ꡀ..ꡳ
    {0xA930, 0xA946, SC_Rejang, GC_Lo, NULL}, //  (Excluded) ꤰ..ꥆ
    {0x10000, 0x1000B, SC_Linear_B, GC_Lo, NULL}, //  (Excluded) 𐀀..𐀋
    {0x1000D, 0x10026, SC_Linear_B, GC_Lo, NULL}, //  (Excluded) 𐀍..𐀦
    {0x10028, 0x1003A, SC_Linear_B, GC_Lo, NULL}, //  (Excluded) 𐀨..𐀺
    {0x1003C, 0x1003D, SC_Linear_B, GC_Lo, NULL}, //  (Excluded) 𐀼..𐀽
    {0x1003F, 0x1004D, SC_Linear_B, GC_Lo, NULL}, //  (Excluded) 𐀿..𐁍
    {0x10050, 0x1005D, SC_Linear_B, GC_Lo, NULL}, //  (Excluded) 𐁐..𐁝
    {0x10080, 0x100FA, SC_Linear_B, GC_Lo, NULL}, //  (Excluded) 𐂀..𐃺
    {0x10280, 0x1029C, SC_Lycian, GC_Lo, NULL}, //  (Excluded) 𐊀..𐊜
    {0x102A0, 0x102D0, SC_Carian, GC_Lo, NULL}, //  (Excluded) 𐊠..𐋐
    {0x10300, 0x1031F, SC_Old_Italic, GC_Lo, NULL}, //  (Excluded) 𐌀..𐌟
    {0x1032D, 0x1032F, SC_Old_Italic, GC_Lo, NULL}, //  (Excluded) 𐌭..𐌯
    {0x10331, 0x1034A, SC_Gothic, GC_V, NULL}, //  (Excluded) 𐌱..𐍊
    {0x10350, 0x10375, SC_Old_Permic, GC_Lo, NULL}, //  (Excluded) 𐍐..𐍵
    {0x10380, 0x1039D, SC_Ugaritic, GC_Lo, NULL}, //  (Excluded) 𐎀..𐎝
    {0x103A0, 0x103C3, SC_Old_Persian, GC_Lo, NULL}, //  (Excluded) 𐎠..𐏃
    {0x103C8, 0x103CF, SC_Old_Persian, GC_Lo, NULL}, //  (Excluded) 𐏈..𐏏
    {0x103D1, 0x103D5, SC_Old_Persian, GC_Nl, NULL}, //  (Excluded) 𐏑..𐏕
    {0x10400, 0x1044F, SC_Deseret, GC_L, NULL}, //  (Excluded) 𐐀..𐑏
    {0x10451, 0x1047F, SC_Shavian, GC_Lo, NULL}, //  (Excluded) 𐑑..𐑿
    {0x10481, 0x1049D, SC_Osmanya, GC_Lo, NULL}, //  (Excluded) 𐒁..𐒝
    {0x10500, 0x10527, SC_Elbasan, GC_Lo, NULL}, //  (Excluded) 𐔀..𐔧
    {0x10530, 0x10563, SC_Caucasian_Albanian, GC_Lo, NULL}, //  (Excluded) 𐔰..𐕣
    {0x10570, 0x1057A, SC_Vithkuqi, GC_Lu, NULL}, //  (Excluded) 𐕰..𐕺
    {0x1057C, 0x1058A, SC_Vithkuqi, GC_Lu, NULL}, //  (Excluded) 𐕼..𐖊
    {0x1058C, 0x10592, SC_Vithkuqi, GC_Lu, NULL}, //  (Excluded) 𐖌..𐖒
    {0x10594, 0x10595, SC_Vithkuqi, GC_Lu, NULL}, //  (Excluded) 𐖔..𐖕
    {0x10597, 0x105A1, SC_Vithkuqi, GC_Ll, NULL}, //  (Excluded) 𐖗..𐖡
    {0x105A3, 0x105B1, SC_Vithkuqi, GC_Ll, NULL}, //  (Excluded) 𐖣..𐖱
    {0x105B3, 0x105B9, SC_Vithkuqi, GC_Ll, NULL}, //  (Excluded) 𐖳..𐖹
    {0x105BB, 0x105BC, SC_Vithkuqi, GC_Ll, NULL}, //  (Excluded) 𐖻..𐖼
    {0x10600, 0x10736, SC_Linear_A, GC_Lo, NULL}, //  (Excluded) 𐘀..𐜶
    {0x10740, 0x10755, SC_Linear_A, GC_Lo, NULL}, //  (Excluded) 𐝀..𐝕
    {0x10760, 0x10767, SC_Linear_A, GC_Lo, NULL}, //  (Excluded) 𐝠..𐝧
    {0x10800, 0x10805, SC_Cypriot, GC_Lo, NULL}, //  (Excluded) 𐠀..𐠅
    {0x10808, 0x10808, SC_Cypriot, GC_Lo, NULL}, //  (Excluded) 𐠈
    {0x1080A, 0x10835, SC_Cypriot, GC_Lo, NULL}, //  (Excluded) 𐠊..𐠵
    {0x10837, 0x10838, SC_Cypriot, GC_Lo, NULL}, //  (Excluded) 𐠷..𐠸
    {0x1083C, 0x1083C, SC_Cypriot, GC_Lo, NULL}, //  (Excluded) 𐠼
    {0x1083F, 0x1083F, SC_Cypriot, GC_Lo, NULL}, //  (Excluded) 𐠿
    {0x10841, 0x10855, SC_Imperial_Aramaic, GC_Lo, NULL}, //  (Excluded) 𐡁..𐡕
    {0x10860, 0x10876, SC_Palmyrene, GC_Lo, NULL}, //  (Excluded) 𐡠..𐡶
    {0x10880, 0x1089E, SC_Nabataean, GC_Lo, NULL}, //  (Excluded) 𐢀..𐢞
    {0x108E0, 0x108F2, SC_Hatran, GC_Lo, NULL}, //  (Excluded) 𐣠..𐣲
    {0x108F4, 0x108F5, SC_Hatran, GC_Lo, NULL}, //  (Excluded) 𐣴..𐣵
    {0x10900, 0x10915, SC_Phoenician, GC_Lo, NULL}, //  (Excluded) 𐤀..𐤕
    {0x10920, 0x10939, SC_Lydian, GC_Lo, NULL}, //  (Excluded) 𐤠..𐤹
    {0x10980, 0x1099F, SC_Meroitic_Hieroglyphs, GC_Lo, NULL}, //  (Excluded) 𐦀..𐦟
    {0x109A1, 0x109B7, SC_Meroitic_Cursive, GC_Lo, NULL}, //  (Excluded) 𐦡..𐦷
    {0x109BE, 0x109BF, SC_Meroitic_Cursive, GC_Lo, NULL}, //  (Excluded) 𐦾..𐦿
    {0x10A00, 0x10A00, SC_Kharoshthi, GC_Lo, NULL}, //  (Excluded) 𐨀
    {0x10A10, 0x10A13, SC_Kharoshthi, GC_Lo, NULL}, //  (Excluded) 𐨐..𐨓
    {0x10A15, 0x10A17, SC_Kharoshthi, GC_Lo, NULL}, //  (Excluded) 𐨕..𐨗
    {0x10A19, 0x10A35, SC_Kharoshthi, GC_Lo, NULL}, //  (Excluded) 𐨙..𐨵
    {0x10A60, 0x10A7C, SC_Old_South_Arabian, GC_Lo, NULL}, //  (Excluded) 𐩠..𐩼
    {0x10A80, 0x10A9C, SC_Old_North_Arabian, GC_Lo, NULL}, //  (Excluded) 𐪀..𐪜
    {0x10AC0, 0x10AC7, SC_Manichaean, GC_Lo, NULL}, //  (Excluded) 𐫀..𐫇
    {0x10AC9, 0x10AE4, SC_Manichaean, GC_Lo, NULL}, //  (Excluded) 𐫉..𐫤
    {0x10B00, 0x10B35, SC_Avestan, GC_Lo, NULL}, //  (Excluded) 𐬀..𐬵
    {0x10B40, 0x10B55, SC_Inscriptional_Parthian, GC_Lo, NULL}, //  (Excluded) 𐭀..𐭕
    {0x10B60, 0x10B72, SC_Inscriptional_Pahlavi, GC_Lo, NULL}, //  (Excluded) 𐭠..𐭲
    {0x10B80, 0x10B91, SC_Psalter_Pahlavi, GC_Lo, NULL}, //  (Excluded) 𐮀..𐮑
    {0x10C00, 0x10C48, SC_Old_Turkic, GC_Lo, NULL}, //  (Excluded) 𐰀..𐱈
    {0x10C80, 0x10CB2, SC_Old_Hungarian, GC_Lu, NULL}, //  (Excluded) 𐲀..𐲲
    {0x10CC0, 0x10CF2, SC_Old_Hungarian, GC_Ll, NULL}, //  (Excluded) 𐳀..𐳲
    {0x10E80, 0x10EA9, SC_Yezidi, GC_Lo, NULL}, //  (Excluded) 𐺀..𐺩
    {0x10EB0, 0x10EB1, SC_Yezidi, GC_Lo, NULL}, //  (Excluded) 𐺰..𐺱
    {0x10F00, 0x10F1C, SC_Old_Sogdian, GC_Lo, NULL}, //  (Excluded) 𐼀..𐼜
    {0x10F27, 0x10F27, SC_Old_Sogdian, GC_Lo, NULL}, //  (Excluded) 𐼧
    {0x10F30, 0x10F45, SC_Sogdian, GC_Lo, NULL}, //  (Excluded) 𐼰..𐽅
    {0x10F70, 0x10F81, SC_Old_Uyghur, GC_Lo, NULL}, //  (Excluded) 𐽰..𐾁
    {0x10FB0, 0x10FC4, SC_Chorasmian, GC_Lo, NULL}, //  (Excluded) 𐾰..𐿄
    {0x10FE0, 0x10FF6, SC_Elymaic, GC_Lo, NULL}, //  (Excluded) 𐿠..𐿶
    {0x11003, 0x11037, SC_Brahmi, GC_Lo, NULL}, //  (Excluded) 𑀃..𑀷
    {0x11071, 0x11072, SC_Brahmi, GC_Lo, NULL}, //  (Excluded) 𑁱..𑁲
    {0x11075, 0x11075, SC_Brahmi, GC_Lo, NULL}, //  (Excluded) 𑁵
    {0x11083, 0x110AF, SC_Kaithi, GC_Lo, NULL}, //  (Excluded) 𑂃..𑂯
    {0x110D0, 0x110E8, SC_Sora_Sompeng, GC_Lo, NULL}, //  (Excluded) 𑃐..𑃨
    {0x11150, 0x11172, SC_Mahajani, GC_Lo, NULL}, //  (Excluded) 𑅐..𑅲
    {0x11176, 0x11176, SC_Mahajani, GC_Lo, NULL}, //  (Excluded) 𑅶
    {0x11183, 0x111B2, SC_Sharada, GC_Lo, NULL}, //  (Excluded) 𑆃..𑆲
    {0x111C1, 0x111C4, SC_Sharada, GC_Lo, NULL}, //  (Excluded) 𑇁..𑇄
    {0x111DA, 0x111DA, SC_Sharada, GC_Lo, NULL}, //  (Excluded) 𑇚
    {0x111DC, 0x111DC, SC_Sharada, GC_Lo, NULL}, //  (Excluded) 𑇜
    {0x11200, 0x11211, SC_Khojki, GC_Lo, NULL}, //  (Excluded) 𑈀..𑈑
    {0x11213, 0x1122B, SC_Khojki, GC_Lo, NULL}, //  (Excluded) 𑈓..𑈫
    {0x11280, 0x11286, SC_Multani, GC_Lo, NULL}, //  (Excluded) 𑊀..𑊆
    {0x11288, 0x11288, SC_Multani, GC_Lo, NULL}, //  (Excluded) 𑊈
    {0x1128A, 0x1128D, SC_Multani, GC_Lo, NULL}, //  (Excluded) 𑊊..𑊍
    {0x1128F, 0x1129D, SC_Multani, GC_Lo, NULL}, //  (Excluded) 𑊏..𑊝
    {0x1129F, 0x112A8, SC_Multani, GC_Lo, NULL}, //  (Excluded) 𑊟..𑊨
    {0x112B0, 0x112DE, SC_Khudawadi, GC_Lo, NULL}, //  (Excluded) 𑊰..𑋞
    {0x11305, 0x1130C, SC_Grantha, GC_Lo, NULL}, //  (Excluded) 𑌅..𑌌
    {0x1130F, 0x11310, SC_Grantha, GC_Lo, NULL}, //  (Excluded) 𑌏..𑌐
    {0x11313, 0x11328, SC_Grantha, GC_Lo, NULL}, //  (Excluded) 𑌓..𑌨
    {0x1132A, 0x11330, SC_Grantha, GC_Lo, NULL}, //  (Excluded) 𑌪..𑌰
    {0x11332, 0x11333, SC_Grantha, GC_Lo, NULL}, //  (Excluded) 𑌲..𑌳
    {0x11335, 0x11339, SC_Grantha, GC_Lo, NULL}, //  (Excluded) 𑌵..𑌹
    {0x1133D, 0x1133D, SC_Grantha, GC_Lo, NULL}, //  (Excluded) 𑌽
    {0x11350, 0x11350, SC_Grantha, GC_Lo, NULL}, //  (Excluded) 𑍐
    {0x1135D, 0x11361, SC_Grantha, GC_Lo, NULL}, //  (Excluded) 𑍝..𑍡
    {0x11480, 0x114AF, SC_Tirhuta, GC_Lo, NULL}, //  (Excluded) 𑒀..𑒯
    {0x114C4, 0x114C5, SC_Tirhuta, GC_Lo, NULL}, //  (Excluded) 𑓄..𑓅
    {0x114C7, 0x114C7, SC_Tirhuta, GC_Lo, NULL}, //  (Excluded) 𑓇
    {0x11580, 0x115AE, SC_Siddham, GC_Lo, NULL}, //  (Excluded) 𑖀..𑖮
    {0x115D8, 0x115DB, SC_Siddham, GC_Lo, NULL}, //  (Excluded) 𑗘..𑗛
    {0x11600, 0x1162F, SC_Modi, GC_Lo, NULL}, //  (Excluded) 𑘀..𑘯
    {0x11644, 0x11644, SC_Modi, GC_Lo, NULL}, //  (Excluded) 𑙄
    {0x11680, 0x116AA, SC_Takri, GC_Lo, NULL}, //  (Excluded) 𑚀..𑚪
    {0x116B8, 0x116B8, SC_Takri, GC_Lo, NULL}, //  (Excluded) 𑚸
    {0x11700, 0x1171A, SC_Ahom, GC_Lo, NULL}, //  (Excluded) 𑜀..𑜚
    {0x11740, 0x11746, SC_Ahom, GC_Lo, NULL}, //  (Excluded) 𑝀..𑝆
    {0x11800, 0x1182B, SC_Dogra, GC_Lo, NULL}, //  (Excluded) 𑠀..𑠫
    {0x118A0, 0x118DF, SC_Warang_Citi, GC_L, NULL}, //  (Excluded) 𑢠..𑣟
    {0x118FF, 0x118FF, SC_Warang_Citi, GC_Lo, NULL}, //  (Excluded) 𑣿
    {0x11901, 0x11906, SC_Dives_Akuru, GC_Lo, NULL}, //  (Excluded) 𑤁..𑤆
    {0x11909, 0x11909, SC_Dives_Akuru, GC_Lo, NULL}, //  (Excluded) 𑤉
    {0x1190C, 0x11913, SC_Dives_Akuru, GC_Lo, NULL}, //  (Excluded) 𑤌..𑤓
    {0x11915, 0x11916, SC_Dives_Akuru, GC_Lo, NULL}, //  (Excluded) 𑤕..𑤖
    {0x11918, 0x1192F, SC_Dives_Akuru, GC_Lo, NULL}, //  (Excluded) 𑤘..𑤯
    {0x1193F, 0x1193F, SC_Dives_Akuru, GC_Lo, NULL}, //  (Excluded) 𑤿
    {0x11941, 0x11941, SC_Dives_Akuru, GC_Lo, NULL}, //  (Excluded) 𑥁
    {0x119A0, 0x119A7, SC_Nandinagari, GC_Lo, NULL}, //  (Excluded) 𑦠..𑦧
    {0x119AA, 0x119D0, SC_Nandinagari, GC_Lo, NULL}, //  (Excluded) 𑦪..𑧐
    {0x119E1, 0x119E1, SC_Nandinagari, GC_Lo, NULL}, //  (Excluded) 𑧡
    {0x119E3, 0x119E3, SC_Nandinagari, GC_Lo, NULL}, //  (Excluded) 𑧣
    {0x11A00, 0x11A00, SC_Zanabazar_Square, GC_Lo, NULL}, //  (Excluded) 𑨀
    {0x11A0B, 0x11A32, SC_Zanabazar_Square, GC_Lo, NULL}, //  (Excluded) 𑨋..𑨲
    {0x11A3A, 0x11A3A, SC_Zanabazar_Square, GC_Lo, NULL}, //  (Excluded) 𑨺
    {0x11A50, 0x11A50, SC_Soyombo, GC_Lo, NULL}, //  (Excluded) 𑩐
    {0x11A5C, 0x11A89, SC_Soyombo, GC_Lo, NULL}, //  (Excluded) 𑩜..𑪉
    {0x11A9D, 0x11A9D, SC_Soyombo, GC_Lo, NULL}, //  (Excluded) 𑪝
    {0x11AC0, 0x11AF8, SC_Pau_Cin_Hau, GC_Lo, NULL}, //  (Excluded) 𑫀..𑫸
    {0x11C00, 0x11C08, SC_Bhaiksuki, GC_Lo, NULL}, //  (Excluded) 𑰀..𑰈
    {0x11C0A, 0x11C2E, SC_Bhaiksuki, GC_Lo, NULL}, //  (Excluded) 𑰊..𑰮
    {0x11C40, 0x11C40, SC_Bhaiksuki, GC_Lo, NULL}, //  (Excluded) 𑱀
    {0x11C72, 0x11C8F, SC_Marchen, GC_Lo, NULL}, //  (Excluded) 𑱲..𑲏
    {0x11D00, 0x11D06, SC_Masaram_Gondi, GC_Lo, NULL}, //  (Excluded) 𑴀..𑴆
    {0x11D08, 0x11D09, SC_Masaram_Gondi, GC_Lo, NULL}, //  (Excluded) 𑴈..𑴉
    {0x11D0B, 0x11D30, SC_Masaram_Gondi, GC_Lo, NULL}, //  (Excluded) 𑴋..𑴰
    {0x11D46, 0x11D46, SC_Masaram_Gondi, GC_Lo, NULL}, //  (Excluded) 𑵆
    {0x11EE0, 0x11EF2, SC_Makasar, GC_Lo, NULL}, //  (Excluded) 𑻠..𑻲
    {0x12000, 0x12399, SC_Cuneiform, GC_Lo, NULL}, //  (Excluded) 𒀀..𒎙
    {0x12400, 0x1246E, SC_Cuneiform, GC_Nl, NULL}, //  (Excluded) 𒐀..𒑮
    {0x12480, 0x12543, SC_Cuneiform, GC_Lo, NULL}, //  (Excluded) 𒒀..𒕃
    {0x12F90, 0x12FF0, SC_Cypro_Minoan, GC_Lo, NULL}, //  (Excluded) 𒾐..𒿰
    {0x13000, 0x1342E, SC_Egyptian_Hieroglyphs, GC_Lo, NULL}, //  (Excluded) 𓀀..𓐮
    {0x14400, 0x14646, SC_Anatolian_Hieroglyphs, GC_Lo, NULL}, //  (Excluded) 𔐀..𔙆
    {0x16A70, 0x16ABE, SC_Tangsa, GC_Lo, NULL}, //  (Excluded) 𖩰..𖪾
    {0x16AD0, 0x16AED, SC_Bassa_Vah, GC_Lo, NULL}, //  (Excluded) 𖫐..𖫭
    {0x16B00, 0x16B2F, SC_Pahawh_Hmong, GC_Lo, NULL}, //  (Excluded) 𖬀..𖬯
    {0x16B40, 0x16B43, SC_Pahawh_Hmong, GC_Lm, NULL}, //  (Excluded) 𖭀..𖭃
    {0x16B63, 0x16B77, SC_Pahawh_Hmong, GC_Lo, NULL}, //  (Excluded) 𖭣..𖭷
    {0x16B7D, 0x16B8F, SC_Pahawh_Hmong, GC_Lo, NULL}, //  (Excluded) 𖭽..𖮏
    {0x16E40, 0x16E7F, SC_Medefaidrin, GC_L, NULL}, //  (Excluded) 𖹀..𖹿
    {0x16FE0, 0x16FE0, SC_Tangut, GC_Lm, NULL}, //  (Excluded) 𖿠
    {0x17000, 0x187F7, SC_Tangut, GC_Lo, NULL}, //  (Excluded) 𗀀..𘟷
    {0x18800, 0x18AFF, SC_Tangut, GC_Lo, NULL}, //  (Excluded) 𘠀..𘫿
    {0x18B01, 0x18CD5, SC_Khitan_Small_Script, GC_Lo, NULL}, //  (Excluded) 𘬁..𘳕
    {0x18D00, 0x18D08, SC_Tangut, GC_Lo, NULL}, //  (Excluded) 𘴀..𘴈
    {0x1B170, 0x1B2FB, SC_Nushu, GC_Lo, NULL}, //  (Excluded) 𛅰..𛋻
    {0x1BC00, 0x1BC6A, SC_Duployan, GC_Lo, NULL}, //  (Excluded) 𛰀..𛱪
    {0x1BC70, 0x1BC7C, SC_Duployan, GC_Lo, NULL}, //  (Excluded) 𛱰..𛱼
    {0x1BC80, 0x1BC88, SC_Duployan, GC_Lo, NULL}, //  (Excluded) 𛲀..𛲈
    {0x1BC90, 0x1BC99, SC_Duployan, GC_Lo, NULL}, //  (Excluded) 𛲐..𛲙
    {0x1E290, 0x1E2AD, SC_Toto, GC_Lo, NULL}, //  (Excluded) 𞊐..𞊭
    {0x1E800, 0x1E8C4, SC_Mende_Kikakui, GC_Lo, NULL}, //  (Excluded) 𞠀..𞣄
};
#else
extern const struct sc_c26 safec26_excl_start_list[191];
#endif
// 158 ranges, 33 singles, 14926 codepoints

// Only excluded scripts, XID_Continue,!XID_Start, more IDTypes, NFC and !MARK
#ifndef EXTERN_SCRIPTS
const struct sc_c26 safec26_excl_cont_list[] = {
    {0x1810, 0x1819, SC_Mongolian, GC_Nd, NULL}, //  (Excluded) ᠐..᠙
    {0x104A0, 0x104A9, SC_Osmanya, GC_Nd, NULL}, //  (Excluded) 𐒠..𐒩
    {0x11066, 0x1106F, SC_Brahmi, GC_Nd, NULL}, //  (Excluded) 𑁦..𑁯
    {0x110F0, 0x110F9, SC_Sora_Sompeng, GC_Nd, NULL}, //  (Excluded) 𑃰..𑃹
    {0x111D0, 0x111D9, SC_Sharada, GC_Nd, NULL}, //  (Excluded) 𑇐..𑇙
    {0x112F0, 0x112F9, SC_Khudawadi, GC_Nd, NULL}, //  (Excluded) 𑋰..𑋹
    {0x114D0, 0x114D9, SC_Tirhuta, GC_Nd, NULL}, //  (Excluded) 𑓐..𑓙
    {0x11650, 0x11659, SC_Modi, GC_Nd, NULL}, //  (Excluded) 𑙐..𑙙
    {0x116C0, 0x116C9, SC_Takri, GC_Nd, NULL}, //  (Excluded) 𑛀..𑛉
    {0x11730, 0x11739, SC_Ahom, GC_Nd, NULL}, //  (Excluded) 𑜰..𑜹
    {0x118E0, 0x118E9, SC_Warang_Citi, GC_Nd, NULL}, //  (Excluded) 𑣠..𑣩
    {0x11950, 0x11959, SC_Dives_Akuru, GC_Nd, NULL}, //  (Excluded) 𑥐..𑥙
    {0x11C50, 0x11C59, SC_Bhaiksuki, GC_Nd, NULL}, //  (Excluded) 𑱐..𑱙
    {0x11D50, 0x11D59, SC_Masaram_Gondi, GC_Nd, NULL}, //  (Excluded) 𑵐..𑵙
    {0x16AC0, 0x16AC9, SC_Tangsa, GC_Nd, NULL}, //  (Excluded) 𖫀..𖫉
    {0x16B50, 0x16B59, SC_Pahawh_Hmong, GC_Nd, NULL}, //  (Excluded) 𖭐..𖭙
}; // 16 ranges, 0 singles, 144 codepoints
#else
extern const struct sc_c26 safec26_excl_cont_list[16];
#endif

// Shorter MEDIAL list for safec26.
// safec26_start/cont + MEDIAL
#ifndef EXTERN_SCRIPTS
const struct range_bool safec26_medial_list[] = {
}; // 0 ranges, 0 singles, 0 codepoints
#else
extern const struct range_bool safec26_medial_list[0];
#endif
