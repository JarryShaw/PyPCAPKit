# -*- coding: utf-8 -*-


# Registration Types
_REG_TYPE = {
    0 : 'Unassigned [0] (IETF Review)',
    1 : 'RENDEZVOUS',                                                           # [RFC 8004]
    2 : 'RELAY_UDP_HIP',                                                        # [RFC 5770]
    3 : 'Unassigned [3] (IETF Review)',
    4 : 'Unassigned [4] (IETF Review)',
    5 : 'Unassigned [5] (IETF Review)',
    6 : 'Unassigned [6] (IETF Review)',
    7 : 'Unassigned [7] (IETF Review)',
    8 : 'Unassigned [8] (IETF Review)',
    9 : 'Unassigned [9] (IETF Review)',
   10 : 'Unassigned [10] (IETF Review)',
   11 : 'Unassigned [11] (IETF Review)',
   12 : 'Unassigned [12] (IETF Review)',
   13 : 'Unassigned [13] (IETF Review)',
   14 : 'Unassigned [14] (IETF Review)',
   15 : 'Unassigned [15] (IETF Review)',
   16 : 'Unassigned [16] (IETF Review)',
   17 : 'Unassigned [17] (IETF Review)',
   18 : 'Unassigned [18] (IETF Review)',
   19 : 'Unassigned [19] (IETF Review)',
   20 : 'Unassigned [20] (IETF Review)',
   21 : 'Unassigned [21] (IETF Review)',
   22 : 'Unassigned [22] (IETF Review)',
   23 : 'Unassigned [23] (IETF Review)',
   24 : 'Unassigned [24] (IETF Review)',
   25 : 'Unassigned [25] (IETF Review)',
   26 : 'Unassigned [26] (IETF Review)',
   27 : 'Unassigned [27] (IETF Review)',
   28 : 'Unassigned [28] (IETF Review)',
   29 : 'Unassigned [29] (IETF Review)',
   30 : 'Unassigned [30] (IETF Review)',
   31 : 'Unassigned [31] (IETF Review)',
   32 : 'Unassigned [32] (IETF Review)',
   33 : 'Unassigned [33] (IETF Review)',
   34 : 'Unassigned [34] (IETF Review)',
   35 : 'Unassigned [35] (IETF Review)',
   36 : 'Unassigned [36] (IETF Review)',
   37 : 'Unassigned [37] (IETF Review)',
   38 : 'Unassigned [38] (IETF Review)',
   39 : 'Unassigned [39] (IETF Review)',
   40 : 'Unassigned [40] (IETF Review)',
   41 : 'Unassigned [41] (IETF Review)',
   42 : 'Unassigned [42] (IETF Review)',
   43 : 'Unassigned [43] (IETF Review)',
   44 : 'Unassigned [44] (IETF Review)',
   45 : 'Unassigned [45] (IETF Review)',
   46 : 'Unassigned [46] (IETF Review)',
   47 : 'Unassigned [47] (IETF Review)',
   48 : 'Unassigned [48] (IETF Review)',
   49 : 'Unassigned [49] (IETF Review)',
   50 : 'Unassigned [50] (IETF Review)',
   51 : 'Unassigned [51] (IETF Review)',
   52 : 'Unassigned [52] (IETF Review)',
   53 : 'Unassigned [53] (IETF Review)',
   54 : 'Unassigned [54] (IETF Review)',
   55 : 'Unassigned [55] (IETF Review)',
   56 : 'Unassigned [56] (IETF Review)',
   57 : 'Unassigned [57] (IETF Review)',
   58 : 'Unassigned [58] (IETF Review)',
   59 : 'Unassigned [59] (IETF Review)',
   60 : 'Unassigned [60] (IETF Review)',
   61 : 'Unassigned [61] (IETF Review)',
   62 : 'Unassigned [62] (IETF Review)',
   63 : 'Unassigned [63] (IETF Review)',
   64 : 'Unassigned [64] (IETF Review)',
   65 : 'Unassigned [65] (IETF Review)',
   66 : 'Unassigned [66] (IETF Review)',
   67 : 'Unassigned [67] (IETF Review)',
   68 : 'Unassigned [68] (IETF Review)',
   69 : 'Unassigned [69] (IETF Review)',
   70 : 'Unassigned [70] (IETF Review)',
   71 : 'Unassigned [71] (IETF Review)',
   72 : 'Unassigned [72] (IETF Review)',
   73 : 'Unassigned [73] (IETF Review)',
   74 : 'Unassigned [74] (IETF Review)',
   75 : 'Unassigned [75] (IETF Review)',
   76 : 'Unassigned [76] (IETF Review)',
   77 : 'Unassigned [77] (IETF Review)',
   78 : 'Unassigned [78] (IETF Review)',
   79 : 'Unassigned [79] (IETF Review)',
   80 : 'Unassigned [80] (IETF Review)',
   81 : 'Unassigned [81] (IETF Review)',
   82 : 'Unassigned [82] (IETF Review)',
   83 : 'Unassigned [83] (IETF Review)',
   84 : 'Unassigned [84] (IETF Review)',
   85 : 'Unassigned [85] (IETF Review)',
   86 : 'Unassigned [86] (IETF Review)',
   87 : 'Unassigned [87] (IETF Review)',
   88 : 'Unassigned [88] (IETF Review)',
   89 : 'Unassigned [89] (IETF Review)',
   90 : 'Unassigned [90] (IETF Review)',
   91 : 'Unassigned [91] (IETF Review)',
   92 : 'Unassigned [92] (IETF Review)',
   93 : 'Unassigned [93] (IETF Review)',
   94 : 'Unassigned [94] (IETF Review)',
   95 : 'Unassigned [95] (IETF Review)',
   96 : 'Unassigned [96] (IETF Review)',
   97 : 'Unassigned [97] (IETF Review)',
   98 : 'Unassigned [98] (IETF Review)',
   99 : 'Unassigned [99] (IETF Review)',
  100 : 'Unassigned [100] (IETF Review)',
  101 : 'Unassigned [101] (IETF Review)',
  102 : 'Unassigned [102] (IETF Review)',
  103 : 'Unassigned [103] (IETF Review)',
  104 : 'Unassigned [104] (IETF Review)',
  105 : 'Unassigned [105] (IETF Review)',
  106 : 'Unassigned [106] (IETF Review)',
  107 : 'Unassigned [107] (IETF Review)',
  108 : 'Unassigned [108] (IETF Review)',
  109 : 'Unassigned [109] (IETF Review)',
  110 : 'Unassigned [110] (IETF Review)',
  111 : 'Unassigned [111] (IETF Review)',
  112 : 'Unassigned [112] (IETF Review)',
  113 : 'Unassigned [113] (IETF Review)',
  114 : 'Unassigned [114] (IETF Review)',
  115 : 'Unassigned [115] (IETF Review)',
  116 : 'Unassigned [116] (IETF Review)',
  117 : 'Unassigned [117] (IETF Review)',
  118 : 'Unassigned [118] (IETF Review)',
  119 : 'Unassigned [119] (IETF Review)',
  120 : 'Unassigned [120] (IETF Review)',
  121 : 'Unassigned [121] (IETF Review)',
  122 : 'Unassigned [122] (IETF Review)',
  123 : 'Unassigned [123] (IETF Review)',
  124 : 'Unassigned [124] (IETF Review)',
  125 : 'Unassigned [125] (IETF Review)',
  126 : 'Unassigned [126] (IETF Review)',
  127 : 'Unassigned [127] (IETF Review)',
  128 : 'Unassigned [128] (IETF Review)',
  129 : 'Unassigned [129] (IETF Review)',
  130 : 'Unassigned [130] (IETF Review)',
  131 : 'Unassigned [131] (IETF Review)',
  132 : 'Unassigned [132] (IETF Review)',
  133 : 'Unassigned [133] (IETF Review)',
  134 : 'Unassigned [134] (IETF Review)',
  135 : 'Unassigned [135] (IETF Review)',
  136 : 'Unassigned [136] (IETF Review)',
  137 : 'Unassigned [137] (IETF Review)',
  138 : 'Unassigned [138] (IETF Review)',
  139 : 'Unassigned [139] (IETF Review)',
  140 : 'Unassigned [140] (IETF Review)',
  141 : 'Unassigned [141] (IETF Review)',
  142 : 'Unassigned [142] (IETF Review)',
  143 : 'Unassigned [143] (IETF Review)',
  144 : 'Unassigned [144] (IETF Review)',
  145 : 'Unassigned [145] (IETF Review)',
  146 : 'Unassigned [146] (IETF Review)',
  147 : 'Unassigned [147] (IETF Review)',
  148 : 'Unassigned [148] (IETF Review)',
  149 : 'Unassigned [149] (IETF Review)',
  150 : 'Unassigned [150] (IETF Review)',
  151 : 'Unassigned [151] (IETF Review)',
  152 : 'Unassigned [152] (IETF Review)',
  153 : 'Unassigned [153] (IETF Review)',
  154 : 'Unassigned [154] (IETF Review)',
  155 : 'Unassigned [155] (IETF Review)',
  156 : 'Unassigned [156] (IETF Review)',
  157 : 'Unassigned [157] (IETF Review)',
  158 : 'Unassigned [158] (IETF Review)',
  159 : 'Unassigned [159] (IETF Review)',
  160 : 'Unassigned [160] (IETF Review)',
  161 : 'Unassigned [161] (IETF Review)',
  162 : 'Unassigned [162] (IETF Review)',
  163 : 'Unassigned [163] (IETF Review)',
  164 : 'Unassigned [164] (IETF Review)',
  165 : 'Unassigned [165] (IETF Review)',
  166 : 'Unassigned [166] (IETF Review)',
  167 : 'Unassigned [167] (IETF Review)',
  168 : 'Unassigned [168] (IETF Review)',
  169 : 'Unassigned [169] (IETF Review)',
  170 : 'Unassigned [170] (IETF Review)',
  171 : 'Unassigned [171] (IETF Review)',
  172 : 'Unassigned [172] (IETF Review)',
  173 : 'Unassigned [173] (IETF Review)',
  174 : 'Unassigned [174] (IETF Review)',
  175 : 'Unassigned [175] (IETF Review)',
  176 : 'Unassigned [176] (IETF Review)',
  177 : 'Unassigned [177] (IETF Review)',
  178 : 'Unassigned [178] (IETF Review)',
  179 : 'Unassigned [179] (IETF Review)',
  180 : 'Unassigned [180] (IETF Review)',
  181 : 'Unassigned [181] (IETF Review)',
  182 : 'Unassigned [182] (IETF Review)',
  183 : 'Unassigned [183] (IETF Review)',
  184 : 'Unassigned [184] (IETF Review)',
  185 : 'Unassigned [185] (IETF Review)',
  186 : 'Unassigned [186] (IETF Review)',
  187 : 'Unassigned [187] (IETF Review)',
  188 : 'Unassigned [188] (IETF Review)',
  189 : 'Unassigned [189] (IETF Review)',
  190 : 'Unassigned [190] (IETF Review)',
  191 : 'Unassigned [191] (IETF Review)',
  192 : 'Unassigned [192] (IETF Review)',
  193 : 'Unassigned [193] (IETF Review)',
  194 : 'Unassigned [194] (IETF Review)',
  195 : 'Unassigned [195] (IETF Review)',
  196 : 'Unassigned [196] (IETF Review)',
  197 : 'Unassigned [197] (IETF Review)',
  198 : 'Unassigned [198] (IETF Review)',
  199 : 'Unassigned [199] (IETF Review)',
  200 : 'Unassigned [200] (IETF Review)',
  201 : 'Reserved for Private Use [201] (Reserved for Private Use)',            # [RFC 8003]
  202 : 'Reserved for Private Use [202] (Reserved for Private Use)',            # [RFC 8003]
  203 : 'Reserved for Private Use [203] (Reserved for Private Use)',            # [RFC 8003]
  204 : 'Reserved for Private Use [204] (Reserved for Private Use)',            # [RFC 8003]
  205 : 'Reserved for Private Use [205] (Reserved for Private Use)',            # [RFC 8003]
  206 : 'Reserved for Private Use [206] (Reserved for Private Use)',            # [RFC 8003]
  207 : 'Reserved for Private Use [207] (Reserved for Private Use)',            # [RFC 8003]
  208 : 'Reserved for Private Use [208] (Reserved for Private Use)',            # [RFC 8003]
  209 : 'Reserved for Private Use [209] (Reserved for Private Use)',            # [RFC 8003]
  210 : 'Reserved for Private Use [210] (Reserved for Private Use)',            # [RFC 8003]
  211 : 'Reserved for Private Use [211] (Reserved for Private Use)',            # [RFC 8003]
  212 : 'Reserved for Private Use [212] (Reserved for Private Use)',            # [RFC 8003]
  213 : 'Reserved for Private Use [213] (Reserved for Private Use)',            # [RFC 8003]
  214 : 'Reserved for Private Use [214] (Reserved for Private Use)',            # [RFC 8003]
  215 : 'Reserved for Private Use [215] (Reserved for Private Use)',            # [RFC 8003]
  216 : 'Reserved for Private Use [216] (Reserved for Private Use)',            # [RFC 8003]
  217 : 'Reserved for Private Use [217] (Reserved for Private Use)',            # [RFC 8003]
  218 : 'Reserved for Private Use [218] (Reserved for Private Use)',            # [RFC 8003]
  219 : 'Reserved for Private Use [219] (Reserved for Private Use)',            # [RFC 8003]
  220 : 'Reserved for Private Use [220] (Reserved for Private Use)',            # [RFC 8003]
  221 : 'Reserved for Private Use [221] (Reserved for Private Use)',            # [RFC 8003]
  222 : 'Reserved for Private Use [222] (Reserved for Private Use)',            # [RFC 8003]
  223 : 'Reserved for Private Use [223] (Reserved for Private Use)',            # [RFC 8003]
  224 : 'Reserved for Private Use [224] (Reserved for Private Use)',            # [RFC 8003]
  225 : 'Reserved for Private Use [225] (Reserved for Private Use)',            # [RFC 8003]
  226 : 'Reserved for Private Use [226] (Reserved for Private Use)',            # [RFC 8003]
  227 : 'Reserved for Private Use [227] (Reserved for Private Use)',            # [RFC 8003]
  228 : 'Reserved for Private Use [228] (Reserved for Private Use)',            # [RFC 8003]
  229 : 'Reserved for Private Use [229] (Reserved for Private Use)',            # [RFC 8003]
  230 : 'Reserved for Private Use [230] (Reserved for Private Use)',            # [RFC 8003]
  231 : 'Reserved for Private Use [231] (Reserved for Private Use)',            # [RFC 8003]
  232 : 'Reserved for Private Use [232] (Reserved for Private Use)',            # [RFC 8003]
  233 : 'Reserved for Private Use [233] (Reserved for Private Use)',            # [RFC 8003]
  234 : 'Reserved for Private Use [234] (Reserved for Private Use)',            # [RFC 8003]
  235 : 'Reserved for Private Use [235] (Reserved for Private Use)',            # [RFC 8003]
  236 : 'Reserved for Private Use [236] (Reserved for Private Use)',            # [RFC 8003]
  237 : 'Reserved for Private Use [237] (Reserved for Private Use)',            # [RFC 8003]
  238 : 'Reserved for Private Use [238] (Reserved for Private Use)',            # [RFC 8003]
  239 : 'Reserved for Private Use [239] (Reserved for Private Use)',            # [RFC 8003]
  240 : 'Reserved for Private Use [240] (Reserved for Private Use)',            # [RFC 8003]
  241 : 'Reserved for Private Use [241] (Reserved for Private Use)',            # [RFC 8003]
  242 : 'Reserved for Private Use [242] (Reserved for Private Use)',            # [RFC 8003]
  243 : 'Reserved for Private Use [243] (Reserved for Private Use)',            # [RFC 8003]
  244 : 'Reserved for Private Use [244] (Reserved for Private Use)',            # [RFC 8003]
  245 : 'Reserved for Private Use [245] (Reserved for Private Use)',            # [RFC 8003]
  246 : 'Reserved for Private Use [246] (Reserved for Private Use)',            # [RFC 8003]
  247 : 'Reserved for Private Use [247] (Reserved for Private Use)',            # [RFC 8003]
  248 : 'Reserved for Private Use [248] (Reserved for Private Use)',            # [RFC 8003]
  249 : 'Reserved for Private Use [249] (Reserved for Private Use)',            # [RFC 8003]
  250 : 'Reserved for Private Use [250] (Reserved for Private Use)',            # [RFC 8003]
  251 : 'Reserved for Private Use [251] (Reserved for Private Use)',            # [RFC 8003]
  252 : 'Reserved for Private Use [252] (Reserved for Private Use)',            # [RFC 8003]
  253 : 'Reserved for Private Use [253] (Reserved for Private Use)',            # [RFC 8003]
  254 : 'Reserved for Private Use [254] (Reserved for Private Use)',            # [RFC 8003]
  255 : 'Reserved for Private Use [255] (Reserved for Private Use)',            # [RFC 8003]
}
