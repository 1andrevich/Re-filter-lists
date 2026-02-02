#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Step 1 - Word Filter with Enhanced Progress Tracking
- Downloads domains.lst from antifilter.download
- Filters domains using comprehensive fraud keyword patterns

Run:
  python step1-download-and-word-filter.py
"""

import os
import logging
import requests
import re
import time
from pathlib import Path
from typing import Optional
from collections import Counter
from tqdm import tqdm
from colorama import init, Fore, Style, Back

# Initialize colorama
init(autoreset=True)

# Ultimate STRICT keyword list:
FRAUD_KEYWORDS = [
    # --- Original aggressive keywords ---
    r'7kcsn', r'^csn', r'csnonln', r'^casi[cak]', r'onion', r'casssino', r'cazzino', r'ethnobs', r'pr-13.com', r'cassiono', r'freespin', r'p0kerdom', r'sinema.top', r'tortugi.net', r'uensdeyse*', r'bitstarz', 
    r'graniru\.info', r'azureedge\.net', r'^bons', r'cloudfront\.net', r'googleusercontent\.com', r'\.google-cloud\.services$', r'\.appspot\.com$',
    r'login', r'signin', r'bank', r'secure', r'^fresh-', r'^freshc', r'verify', r'k[rp]aken', r'krken', r'^triks', r'account', r'go2me', r'global.nethub.fi', r'global.e-cloud.ch',
    r'baza-knig', r'zorgfilm', r'tartugi', r'hdfilm', r'freehd.com.ua', r'ndfl', r'gosuslugi', r'gogamex', r'gamesgo', r'gamego', r'devushk[iuy]', r'agorov.org', r'bonanza',
    r'billing', r'password', r'invoice', r'wriza.top', r'cosmelina.fr', r'bet', r"^(?!www.pokerstars\.com$).*poker.*", r'darknet', r'slot', r'(?i)^turok-?tv$', r'turkrutv', r'turkseria', r'turktv', r'turk-', r'farm', r'prodoping', r'ruanabol',
    r'invest', r'azart', r'blackjack', r'blackrutor.site', r'lafa.site', r'gudfilm', r'luckyx', r'roulette', r'slots', r'^123tor.ru', r'^cactus', r'^medi[ck]',
    r'winbig', r'777admiral', r'gambl', r'kino-', r'-kino', r'kinokrad', r'kingfilm', r'hd1080', r'hd720', r'marleyshop',
    r'fortuna', r'kinoportal', r'kinoteatr\.life', r'maximiz', r'narko', r'pirat(?!ebay)', r'tiviha-tv', r'wullkan',
    r'rutor-', r'-rutor', r'^rutor.[0-9]', r'123rutor', r'holtfilm', r'films1080', r'123tt', r'qqq-ttss\.su',
    r'labiophile.fr', r'opsforgood.fr', r'^omgomg', r'jackpot', r'1win', r'all-russia-sc', r'run2me.pro', r'fastly.net', r'credit',
    r'admiralx', r'es[ck]ort', r'kinogo', r'striptiz', r'zalipni.pro', r'zalipni.uno', r'sinema2\.top', r'semyanich', r'kinoplay', r'play',
    r'kinoz', r'igrovieavtomati', r'massa[gj]', r'stavki', r'dosug', r'vulcan', r'sloty', r'p[uy]tan[aiyu]',
    r'prost1', r'intim', r'shalav[aiy]', r'prostit[uy]t*', r'ritual', r'malvink[iay]',
    r'kokain', r'xanax', r'dragonmoney', r'money-', r'xanaks', r'kinoxa', r'baskino', r'kinovod', r'anasha', r'alfaseed*', r'^seed*',
    r'rezka', r'pin-up', r'kisk[iya]', r'bordel[iuy]', r'devochki', r'^blsp', r'blacsprut', r'blacksprut', r'ganja', r'vselennaya-shluh.com',
    r'igrovyeavtomati', r'p[uy]tan[iay]', r'proctitytki', r'whores', r'rapetub', r'rapeporn', r'animalporn', r'zooporn',
    r'animalzoo',r'zoosex', r'ind[iy]vid[uy]alk[aiu]*',
    r'metadon', r'mefedron', r'krokodil', r'amfetamin', r'xrutor\.org', r'l[0-9]on',
    r'leon-', r'-leon', r'leon.top', r'igrovue-avtomatu-online', r'drug', r'лордфильм',
    r'narcotic', r'meth', r'weed', r'cannabis', r'^rasta', r'vzyatka', r'psych[oe]deli[ck]',
    r'bribe', r'russianbrides', r'chillandridewakepark', r'atelierbeauxartsbordeaux\.fr', r'papinydochki*',
    r'hostmed\.ru', r'maternite-longjumeau\.fr', r'hodyachiemertvecy*', r'igraprestolov*',r'ivanovyivanovy*',
    #igrovieavtomati
    r"igro(?:v(?:ie|ye|iy|i|y)|voi|voy)(?:[-_]?(?:a[wv]?tomat[yi]*(?:online)?|apparat[yi]?|klub|zal|tv|portal|arena|proekty|registracija|bonusi|zals?))?",
    r'duckdns',
    r'linode\.com',
    r'upcloud\.com',
    r'(?i)^[a-z]{5}\.(?:montaubikes|stephanecamillieri|ecuriedugraal|menuiseriemagnieu|coluchekebab|fondation-catalyses|bateau-beatrice)\.fr$',
    #All 3rd level .fr domains
    r'(?i)^[a-z]{5}\.[a-z0-9-]+\.fr$',
    r'\.sl\.pt',
    r'\.biz\.ski',
    r'^kent',
    r'^kisamp',
    r'zemar.top',
    r'apad.top',
    r'game4you.top',
    r'^volna-',
    r'^volna[bc]',
    r'volnadom',
    r'\.sloat\.biz',
    r'\.new\-rutor\.org',
    r'(?i)^rutracker\.[a-z0-9-]+\.[a-z0-9.-]+$',
    r'\.traderc\.biz',
    #Trade
    r'trade',
    r'\.o\-q\.biz',
    r'l0rd',
    r'\.dcge\.biz',
    r'(?i)^[a-z]{3}\.(?:eburgay2|pitergay2|gejmoskva5)\.xyz$',
    r'betcity',
    r'(?i)^\d+\.amdm\.ru$',
    r'(?i)^registr[a-z0-9-]*(?:\.[a-z0-9-]+)*$',
    r'(?i)^as\d+\.online-stars\.org$',
    r'(?i)^b\d+\.liveball\d+\.ga$',
    r'liveball\.(?:pro|cc|st)',
    r'(?i)^s\d+\.skladchik\.one$',
    r'skladchikcom',
    r'^skladchik',
    r'(?i)^[a-z]\d{1,2}\.(?:skladchikcom\.org|skladchikcom\.com|slivschool\.com)$',
    r'^(?!(?:news\.)?zerkalo\.io$).*zerkalo',
    r'arutor.site',
    r'bonus',
    r'^daddy',
    r'^rusalco24-',
    r'^rusalco-',
    #Start Prefix
    r'^start',
    r'(?i)^start(?:\d+)?\.roboforex\.org$',
    r'oboronprom',
    r'bezdep',
    r'^chek',
    r'borjomi',
    r'-cheki',
    r'chek[isy].'
    r'^kent',
    #Propiska
    r'(?i)propisk[a-z0-9-]*',
    r'(?i)^fresh\d+(?:\.[a-z0-9-]+)*\.[a-z]{2,}$',
    r'relax',
    r'onlinekent',
    r'studi-dock',
    r'real-pump',
    r'(?i)^rutor\.[a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})*$',
    #Online Prefix
    r'^online',
    r'sllava',
    r'^ar[kc]ada',
    r'^gamma',
    r'^robot',
    r'^get-x',
    r'^earn',
    r'^fruit',
    r'fei',
    r'^clubnika',
    r'^grand',
    r'^jozz',
    r'thejozz',
    r'^jet',
    r'jetfilm',
    r'luckjet',
    r'^monro',
    r'official.',
    r'^premium',
    r'money',
    r'^mfc-',
    r'^miner',
    r'-miner',
    r'loan',
    r'monkey',
    r'^top\d{1,2}$',
    r'(?i)^top-?\d{1,2}[a-z0-9.-]*\.[a-z]{2,}',
    r'^top-',
    r'topcsn',
    r'^rox',
    r'^turbo',
    r'^starda',
    r'turbofilm',
    r'^tnt',
    r'^uslugi',
    r'zigzag',
    r'zenitbet',
    r'sykaaa',
    r'(?i)(?:serial|serii|smotret|sezon)[a-z0-9-]*',
    r'serial',
    r'winline',
    r'wiqosak',
    r'paripartners',
    r'parimatch',
    r'^vegas',
    r'ligastavok', r'liga\-stavok',
    r'baltplay',
    r'leonbet',
    #Gold
    r'gold',
    #Lordsfilm
    r'l+o*rd?-?s?f+i+l+m?s?',
    r'ru\.leon',
    r'ru\.adleon',
    r'leonaccess',
    r'leon\-[0-9]{3}',
    r'pm\-[0-9]{2,3}\.',
    r'mf\-[0-9]{2,3}\.online',
    r'fon\-[0-9]{2,3}\.',
    r'most.{3}\.',
    r'^canabi',
    r'canabis',
    r'bcity\-',
    r'1x\-',
    r'^1xbet[^.]',
    r'^1xbet\-',
    r'1xgames',
    r'1xmob',
    r'bk\-info',
    r'^dark',
    r'bkinfo',
    r'marathon',
    #VK17
    r'(?i)^vk-?\d{1,2}(?:-?at)?\.[a-z]{2,}$',
    r'gaminator',
    r'^royal',
    r'casin[0-9]',
    r'casiinoo',
    r'goldenstar',
    r'marafon',
    r'olimp\-tv\.org',
    r'olimp',
    r'kasino',
    r'anaboli[ck]',
    r'depozit',
    r'[ck]asino',
    r'admiral',
    r'avtomat',
    r'igrat',
    r'^igra',
    r'azart',
    r'sloty',
    r'bet\-boom',
    r'^kometa',
    r'betsbc',
    r'^bk\-',
    r'zakazat',
    #FX Risky
    r'fx',
    #Global prefix?
    r'^global',
    r'capital',
    r'(?i)crypto-?boss[a-z0-9-]*',
    r'^bkr',
    r'bkinf0',
    r'bukmeker',
    r'ruletka',
    r'profit',
    #Golden
    r'golden',
    r'^vlc',
    r'^vlk',
    r'eldorado',
    r'lotto',
    r'lottery',
    r'fbmetrix',
    r'^trix',
    r'trix.fun',
    r'offrusite',
    r'slsermik',
    r'fon\-bet',
    r'^hydra[0-9]{2,3}',
    r'\bkilogram(?:\.\d+top\.click|(?:club)?\d+\.ru|-\w+\.ru)\b',
    r'^livetv[0-9]{2,3}',
    r'(?:sc\.)?livetv\d+\.me',
    r'cdn\.livetv[0-9]{3}\.me',
    r'^melm',
    r'^mf\-[0-9]{2}',
    r'^most',
    r'^pari\-',
    r'^pokerdom',
    r'(?iu)^ru\d{2}(?:\d)?\.[\w-]+(?:\.[\w-]+)+$',
    #Read prefix
    r'(?i)^read\d+\.w\d+\.(?:lovereads?|loveread|flibusta)\.(?:ru|fun|life)$',
    r'(?i)\bpo[0-9]?ker-[a-z0-9-]+-(?:bn|ben)\.xyz\b',
    r'spravka',
    r'mossst',
    r'mostbet',
    r'd[ij]plom',
    r'pharaon',
    r'fortun[ae]',
    r'^rotate',
    r'^ref.{5}\.',
    r'play\-',
    r'^1w.{3,4}\.',
    r"^7k[0-9a-z]+\.((?:buzz)|(?:top)|(?:pro))$",
    r'^mylove[0-9]{2,3}\.',
    #Mirrors
    r"^\d+w[-a-z]+\.((?:life)|(?:top))$",
    r'^mirror[0-9]{2,3}\.',
    r'thebellmirror',
    r'^mob.{3,4}\.',
    r'^\w*\.?kometalanding\.com$',
    r'^\w*\.doramalive\.news$',
    r'^vv-one\d+\.com$',
    r'^vv-one\d+\.life$',
    r"^[^.]+(?:\.[^.]+)+\.aptoide\.com$",
    r"^[^.]+(?:\.[^.]+)+\.mp3-tut\.biz$",
    r"^[^.]+(?:\.[^.]+)+\.uptodown\.com$",
    r"^[^.]+(?:\.[^.]+)+\.do4a\.me$",
    r"^[^.]+(?:\.[^.]+)+\.a-markets\.org$",
    r'^kilogram\d+\.ru$',
    r'^kilogramclub\d+\.ru$',
    r'^\d*orca\d*\.(com|vip|club|tv|co|ru|es|org|top|pw)$',
    r'^n\w*\.hdreska\.cam$',
    r"^lp-[^.]+\.fon-infosport\.info$",
    r"^[^.]+\.animebesst\.org$",
    r"^[^.]+\.lafa\.name$", 
    r"^k[^.]*\.liveball\.bz$", 
    r"^link[^.]*\.torrent-games\.su$",      
    r"^n[^.]*\.tevas[^.]*\.one$",               
    r"^(?!xvideos\.com$)(?:[^.]+\.)+xvideos[^.]*\.com$",                
    r"^n[^.]*\.oxxyfilm\.club$",                
    r"^v[^.]*\.skladchik\.org$",
    r"^[^.]*ebalka\.ru\.actor$",
    r'^n\w*\.nukino\.club$',
    r'^my\w*\.roboforex\.org$',
    r'^s\w*\.zapret\.me$',
    r'^\d+\.torrent24\.name$',
    r'hydra',
    r'spravok',
    r'spravka',
    r'zenit',
    r'zakladki',
    r'vullcan',
    r'vulslots',
    r'vulwinners',
    r'slots',
    r'sllot',
    r'traffaccess',
    r'tide24',
    r'swleon',
    r'sportingbull',
    r'sokol\-24',
    r'silmag',
    r'faraon',
    r'marbet',
    r'prof[iy]',
    r'jackpot',
    r'semyanich',
    r'semena',
    r'^shishk[iy]',
    r'[wv][uy]l[ck]an*',
    r'bukvaved',
    r'rastarasha',
    r'seed-',
    r'-seed',
    r'seedee',
    r'[ck]a[0-9][il1]no',
    r'kinogb',
    r'vlk\-slots',
    r'^vip',
    r'zhukiserial',
    r'rutorg',
    #R7
    r'^r7(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*$',
    r'^serial(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*$',
    r'azartplay',
    r'bbplay2017',
    r'baltplay2017',
    r'hiwager',
    r'seedbanda',
    r'123tor.ru',
    r'pinco',
    r'^alco',
    r'^www\.deviantart\.com$',
    r'\.r\.cloudfront\.net',
    r'\*',
    r'\\',
    r'multikland\.net',
    r'synchroncode\.com',
    r'placehere\.link',
    r'delivembed\.cc',
    r'offsite',
    r'svetacdn\.in',
    r'^a[bdfk]\-[0-9]{5}',
    r'^azimob[0-9]{5}',
    r'^bets-.{2}-.{5}\.',
    r'^betwinner\-',
    r'pharm',
    r'^gg[0-9]{2,3}\.bet',
    r'^tvmi[a-z]\.online$',
    r'r7-[0-9]{2,3}',
    r'goldfishka[0-9]{2,3}\.',
    r'kinovod[0-9]{2,3}\.cc',
    r'lite\-1x',
    r'livetv[0-9]{2,3}\.me',
    r'loot[0-9]{2,3}\.bet',
    r'melbet\-',
    r'^ox\-[0-9]{5}',
    r'partypoker[0-9]{3,5}\.com',
    r'pin\-up[0-9]{2,3}\.',
    r'zfilm',
    r'appspot\.online',
    #HD Prefix (like hd4. hd5.)
    r'(?i)^hd\d{1,3}\.[a-z0-9-]+\.[a-z]{2,}$',
    r'run.app',
    r'al[ck]o.*[0-9]{2,3}\.',
    r'x\-1xbet\-',
    r'wlnstar',
    r'^[vw][uoy]l{1,2}[ck]an[^.]*',
    r'wlnsport',
    r'winmaster',
    r'winbets',
    r'winbetline',
    r'vigronn',
    r'viagravnn',
    r'vegas\-grand',
    r'vavada',
    #Short GW,GX Domains
    r'(?i)^g[wx][a-z0-9]{1,6}\.[a-z]{2,}$',
    r'teh[ hx]osmotr',
    r'udosto[ vw]verenie',
    r'(?i)udosto[vw]eren[a-z0-9-]*',
    r'tabak',
    r'swissking',
    r'sverhestestvennoe',
    r'^super',
    r'^study\-',
    r'^stream',
    r'strahov',
    r'st\-official',
    r'stavk[ia]',
    r'sprav',
    r'^sslkn',
    r'hdsmotrihd.top',
    r'ooguy.com',
    r'spt\-trejd\-',
    r'sporligtv',
    r'^ourpda',
    r'^spirt\-',
    r'^sol\-',
    r'^solaris',
    r'^sofosbuvir\-',
    r'^slottica',
    #Short Prefixes
    r'^nu[0-9]',
    r'^q[0-9]',
    r'^w[1-9]',
    r'sex-studentki',
    r'seks-studentki',
    r'^slotozal\-',
    r'^selektor',
    r'^selector',
    r'^seedbaza',
    r'^ru\-steroid',
    r'allsteroid',
    r'^steroid',
    r'^refpa',
    r'^putlocker',
    r'prava',
    r'^prawa',
    r'pra[vw]a-online',
    r'online-pra[vw]a',
    r'^onex',
    r'voditel',
    r'^omgomgomg5',
    r'spcs.bio',
    r'^official\-',
    r'^livetv[0-9]*\.',
    r'^lite\-betwin',
    r'^leon\-official',
    r'^leon\-registration',
    r'^kupit',
    r'^kinovod[0-9]*\.',
    r'^eldo',
    r'^bkin\-',
    r'bitstar',
    r'betwinner',
    r'bet1\-x',
    r'balashiha\-grand',
    r'^apl[0-9]*\.',
    r'dot\-xenon\-antonym',
    r'1win\-',
    r'1-{0,1}xredir',
    r'1-{0,1}slot',
    r'1-{0,1}sport',
    r'apteka',
    r'do[ck]tor',
    r'^booi',
    r'^brill',
    r'goldfishka',
    r'777',
    r'888',
    r'cash',
    r'apl[0-9]',
    r'aviator',
    r'azimut',
    r'azino',
    r'betwinnwer\-',
    r'betwin\-',
    r'bitstarz',
    r'bla(?:c)?ksprut',
    r'bongacams',
    r'^bublik',
    r'^cabura',
    r'^champion\-',
    r'^fort\-prav',
    r'^fortprav',
    r'^g\-trade',
    r'^indi[0-9]',
    r'livetv\.me'
    r'^izzi\-',
    r'zhahach',
    r'zeralo\-v\-a\-v\-a\-d\-a',
    r'wawada',
    r'zaliv\-',
    r'zakon\-kamennyh\-dzhungley',
    r'zakis\-',
    r'^zakis',
    r'^zagon',
    r'zarabot',
    r'^vzlom',
    r'^v[uy][l1][ck]',
    r'^vuzinfo',
    r'^up\-x',
    r'^up[0-9]',
    r'^u[0-9][^0-9]',
    r'^trade',
    r'rastishki',
    r'rasta\-',
    r'quantum',
    r'^prava',
    r'1xbet',
    r'1\-xred',
    r'^cheque',
    r'attestat',
    r'^drgn',
    r'^gama',
    r'lombard',
    r'1xslo',
    r'^202[0123]',
    r'^apl',
    r'^apparat',
    r'^avalon',
    #Casino
    r'(?i)[a-z0-9-]*(?:c|k)a[sz]{1,2}[iy1]{0,2}[mn]{0,2}[o0]{1,2}[a-z0-9-]*',
    r'казино',
    r'леон',
    r'^leon',
    r'^azzino',
    r'^casin',
    r'caslno',
    r'(?i)\b[a-z0-9-]*casin(?!g)[a-z0-9-]*',
    r'^bank[^\.]',
    r'^bbrrigght',
    r'^beer',
    r'^belochka',
    r'^bonus',
    r'^100',
    r'^1\-win',
    r'^1xb',
    r'^1\-xb',
    r'^7k\-',
    r'^adm',
    r'^advokat',
    r'flagman',
    r'^agent(?!ura\b)(?![^.]*\.media$)',
    r'^aitfin',
    r'^ai\-',
    r'^alepox',
    r'^alextra',
    r'^alletoper',
    r'allserial',
    r'720-hd.me',
    r'^legzo',
    r'seriall',
    r'fanserial',
    r'rosfirm.info',
    r'^allsteroid',
    r'^allxrtgof',
    r'^alrafiofs',
    r'^amarket',
    r'^anomiks',
    r'ostatsyadruzyamiserial',
    r'^answer',
    r'^apl.*\.me$',
    r'^aqua',
    r'^argo',
    r'^arteif',
    r'^ashoo',
    r'm[ao]r[iy]art[iy]',
    r'^astellia',
    r'^athletic',
    r'^binarium',
    r'^bitstar',
    r'mixfilm',
    r'^bkleon',
    r'^block4',
    r'^720.',
    r'^1080.',
    r'^filmitorrent',
    r'torrent-filmi',
    r'(?i)^[a-z]-tradify\d{1,2}\.site',
    r'^bo11y',
    r'^bollywood',
    #Film prefix like film4.
    r'(?i)\bfilm\d{2,}[a-z0-9-]*\.',
    r'^bomdogmas',
    r'^bomobd',
    r'^victory',
    r'^bs2',
    r'^crystal',
    r'^daclatasvir',
    r'(?i)^kometa\d+\.buzz$',
    r'(?i)^\d+k\d+\.buzz$',
    r'(?i)^\d+k\d+\.online$',
    r'(?i)^w\d+\.zona\.plus$',
    r'(?i)^xo[a-z]{5}\d\.(?:pro|top)$',
    r'^drag',
    r'.rudub.online',
    r'^(?:[A-Za-z0-9-]+\.)+rudub\.today$',
    r'^(?:[A-Za-z0-9-]+\.)+smotri1080\.online$',
    r'^drift',
    r'feya[\w-]*',
    r'^go\-game',
    r'gogame',
    r'bcgame',
    r'bandacas',
    #RU.CAS
    r'by.cas',
    r'ru.cas',
    r'kz.cas',
    r'uz.cas',
    #Games|gamer prefix
    r'^game[sr]',
    r'^jungle',
    r'^klub',
    #Prime
    r'prime',
    r'^elite',
    r'getx',
    r'immediate',
    #Kraken variations
    r'\bkra(?:[1-9]|[1-9][0-9])\b',
    r'^krak',
    r'(?i)\bkra[-_]*\d{2,}[a-z0-9-]*',
    r'\bkpa(?:[1-9]|[1-9][0-9])\b',
    r'(?i)^kr\d{1,2}',
    r'(?i)^kr[a-z]\d{1,2}',
    r'^kpa',
    r'^krl',
    r'^krkn',
    r'^kra-',
    r'(?i)^kra(?:\d{2}(?:at|-cc)?|-[a-z0-9-]+|a[a-z0-9-]*|k[a-z0-9-]*)\.[a-z0-9-]+$',
    r'(?i)\bkrake[a-z0-9.-]*\.[a-z]{2,}',
    r'(?i)\bk{1,6}ra[a-z0-9-]*\d+[a-z0-9-]*',
    r'(?i)\b[1-9]\d*kra[a-z0-9-]*\.[a-z]{2,}',
    r'(?i)\b[1-9]\d*kra[a-z0-9-]*\d+[a-z0-9-]*',
    r'(?i)^https?[-]*-kra[-0-9a-z]*\.[a-z]{2,}(?:\.[a-z]{2,})?$',
    r'(?i)^(?:https?-)?kr[a-z0-9-]*\.[a-z0-9.-]*\.[a-z]{2,}$',
    r'^livetv[0-9]*\.me$',
    r'(?i)tv(?!24)\d{2}\.[a-z]{2,}',
    r'^go2',
    r'^maxbet',
    r'^megamarket',
    r'mos[ck]va\-prava',
    r'(?i)^mos[ck]va[a-z0-9.-]*\.[a-z]{2,}',
    r'pinup',
    r'^pin[ck]',
    r'sex-rach',
    #Seeds
    r'seeds',
    r'sexanketa',
    r'sex-anketa',
    r'^sexx',
    #SEX Prefix like sex4.
    r'(?i)^sex\d+\.[a-z0-9-]*sex[a-z0-9-]*\.[a-z]{2,}$',
    r'(?i)sex\d+\.',
    r'^pin\-up',
    r'pin[ua]p',
    r'spinamba',
    r'^ramen',
    r'^riobet',
    r'^salon',
    r'^sam\-poehal',
    r'^schetchik',
    r'^zorgfilm',
    r'^loftfilm',
    r'bobfilm',
    r'school-',
    r'^zooma',
    r'zetflix',
    r'^zet',
    r'(?i)^site\d+\.[a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})*$',
    r'filmix',
    r'coldfilm',
    r'zercalo',
    r'hdkinoteater',
    r'softonic.ru',
    r'^zakaz',
    r'^trip'
    r'^zagonka',
    r'^xdsakfsad',
    #Cities spam filter
    r'^sochi',
    r'^krasnodar',
    r'-moscow',
    r'moscow-',
    r'^mos-',
    r'^piter',
    r'^vladikavkaz',
    r'^nizhnevartovsk',
    r'^samara',
    r'^abakan',
    r'^orenburg',
    r'^penza',
    #Cities spam filter ^^
    r'(?i)\btrip\d+[a-z0-9-]*\.[a-z]{2,}',
    r'^wowofd',
    r'^win',
    r'^will',
    r'^vtrwo',
    r'^vse',
    r'^vremenn',
    r'^vovan',
    r'^voronezh',
    r'^voenkomat',
    r'^vodka',
    r'^sweet',
    r'^richclub',
    r'^registratsiya',
    r'^official',
    r'^mega5',
    r'^1xlite',
    r'^24',
    r'^888',
    r'^ankustarmios',
    r'^apl',
    r'bxfilm',
    #Film sites
    r'(?i)\bbx?f[i1]lm[\w-]*',
    r'(?i)\b[0-9]f[i1]lm(?:s|i|y|\d)?[\w-]',
    r'^bio',
    r'^black(?!.*(?:news|media))',
    r'^bonga',
    r'^buff',
    #Joy
    r'joy',
    r'^bvfusuv',
    r'^bvidks',
    r'^bwospa',
    r'^caburo',
    #Spin
    r'(?i)\b(?![a-z0-9-]*spine\b)(?![a-z0-9-]*spina\b)[a-z0-9-]*spin(?![ae])[a-z0-9-]*',
    r'^spin',
    r'(?i)spin(?![ae])',
    r'shluhi',
    r'^spir',
    r'^mebel',
    r'^medkn',
    r'clinic',
    r'^med\-kn',
    r'^magn[ei]t',
    r'magnatov',
    r'magiksl',
    r'm3ga',
    r'fairspin',
    r'lucky',
    r'(?i)\bgizb[o0]',
    r'(?i)\bgizb[o0][\w-]*(?:ka|ca)[sz][iy1o0n-]+[\w-]*',
    #Kino
    r'(?i)\bki[nп][o0]',
    #Lord
    r'lord',
    r'(?i)lor+d[-\w]*?(?:s[e3]r[i1][a@][l1]|f[i1][l1][mn]|kino)',
    r'(?i)lo+s+t[-\w]*f[i1][l1][mn]',
    r"(?:^|[-.])[a-z0-9]*win(?!dows?|ter|try|ston|nipeg)[a-z0-9-]*(?=\.|$)"
]

# Preprocess fraud patterns for faster matching
REGEX_SPECIAL_CHARS = set(".^$*+?{}[]\\|()")
SUBSTRING_PATTERNS = []
COMPILED_PATTERNS = []

for _pattern in FRAUD_KEYWORDS:
    try:
        if _pattern.startswith('(?i)') or any(ch in REGEX_SPECIAL_CHARS for ch in _pattern):
            COMPILED_PATTERNS.append(re.compile(_pattern))
        else:
            SUBSTRING_PATTERNS.append(_pattern.lower())
    except re.error:
        # Fallback to substring check if compilation fails
        SUBSTRING_PATTERNS.append(_pattern.lower())


def print_header():
    """Print a colorful header for the script."""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}{'STEP 1 - WORD FILTER WITH ENHANCED PROGRESS TRACKING':^60}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / 'step1_word_filter.log'

logger = logging.getLogger('step1')
if not logger.handlers:
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)


def log_domain_result(domain: str, status: str, keyword: Optional[str] = None) -> None:
    """
    Write a structured line to the log describing how a domain was classified.

    status: "filtered" or "clean"
    keyword: regex pattern that caused the filter (if any)
    """
    if keyword:
        logger.info("RESULT\tstatus=%s\tkeyword=%s\tdomain=%s", status, keyword, domain)
    else:
        logger.info("RESULT\tstatus=%s\tdomain=%s", status, domain)

LOG_LEVELS = {
    'info': logging.INFO,
    'success': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'progress': logging.INFO
}

def print_status(message, status_type="info"):
    """Print colored status messages."""
    colors = {
        "info": Fore.BLUE,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "progress": Fore.CYAN
    }
    log_level = LOG_LEVELS.get(status_type, logging.INFO)
    print(f"{colors.get(status_type, Fore.WHITE)}{message}{Style.RESET_ALL}")
    logger.log(log_level, message)
def run_qc_check(script_dir, clean_domains, filtered_domains):
    """Compare cleaned output against qc_domains.lst and report status."""
    qc_file = script_dir / 'qc_domains.lst'

    if not qc_file.exists():
        print_status(f"?? QC check skipped: {qc_file} not found", "warning")
        return

    print_status("\n?? Running QC check against qc_domains.lst...", "progress")

    with open(qc_file, 'r', encoding='utf-8') as f:
        qc_domains = [line.strip() for line in f if line.strip()]

    if not qc_domains:
        print_status("?? qc_domains.lst is empty. Nothing to verify.", "warning")
        return

    clean_set = {domain.lower() for domain in clean_domains}
    filtered_set = {domain.lower() for domain in filtered_domains}

    present = []
    filtered_hits = []
    missing = []

    for domain in qc_domains:
        domain_lower = domain.lower()
        if domain_lower in clean_set:
            print_status(f"   {domain} -> present in output", "success")
            present.append(domain)
        elif domain_lower in filtered_set:
            print_status(f"   {domain} -> filtered out", "warning")
            filtered_hits.append(domain)
        else:
            print_status(f"   {domain} -> not found in source list", "error")
            missing.append(domain)

    status = "success" if not filtered_hits and not missing else ("warning" if not missing else "error")
    print_status(
        f"?? QC summary: {len(present)} present, {len(filtered_hits)} filtered, {len(missing)} missing",
        status
    )

def main():
    """Main execution function."""
    start_time = time.time()
    print_header()
    
    # Define file paths - main output in same folder as script, filtered files in step 1 folder
    script_dir = Path(__file__).parent
    step1_folder = script_dir / "step 1"
    step1_folder.mkdir(exist_ok=True)
    
    # Downloaded file (in step 1 folder)
    downloaded_file = step1_folder / 'domains_new.lst'
    
    # Main output file (in same folder as script)
    main_output_file = script_dir / 'domains_new_1.lst'
    
    # Filtered files (in step 1 folder)
    filtered_file = step1_folder / 'domains_new_filtered.lst'
    
    print_status(f"📁 Output structure:", "info")
    print_status(f"   Downloaded file: {downloaded_file}", "info")
    print_status(f"   Main output: {main_output_file}", "info")
    print_status(f"   Filtered domains: {filtered_file}", "info")
    print()
    
    # Step 1: Download the domains.lst file
    print_status("🌐 Downloading domains.lst from antifilter.download...", "progress")
    url = "https://antifilter.download/list/domains.lst"
    
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            with open(downloaded_file, 'w', encoding='utf-8') as f:
                f.write(response.text.strip())
            print_status(f"✅ Downloaded and saved {downloaded_file}", "success")
        else:
            raise Exception(f"HTTP Status: {response.status_code}")
    except Exception as e:
        print_status(f"❌ Failed to download domains.lst: {e}", "error")
        return
    
    # Step 2: Process the downloaded file and filter domains
    print_status("🔍 Processing domains and applying fraud keyword filters...", "progress")
    
    if not downloaded_file.exists():
        print_status(f"❌ {downloaded_file} not found. No filtering performed.", "error")
        return
    
    # Read all domains first to get total count
    with open(downloaded_file, 'r', encoding='utf-8') as f:
        all_domains = [line.strip() for line in f if line.strip()]
    
    total_domains = len(all_domains)
    print_status(f"📊 Total domains to process: {total_domains:,}", "info")
    
    # Process domains with progress bar
    clean_domains = []
    filtered_domains = []
    pattern_hits: Counter[str] = Counter()
    
    # Create progress bar with custom styling
    with tqdm(
        total=total_domains,
        desc=f"{Fore.CYAN}Filtering domains{Style.RESET_ALL}",
        unit="domain",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
        colour="cyan"
    ) as pbar:
        for idx, domain in enumerate(all_domains, 1):
            domain_lower = domain.lower()

            matched_keyword = None

            # Fast substring scan
            for substring in SUBSTRING_PATTERNS:
                if substring in domain_lower:
                    matched_keyword = f"substr:{substring}"
                    break

            # Regex scan only if needed
            if matched_keyword is None:
                for pattern in COMPILED_PATTERNS:
                    if pattern.search(domain_lower):
                        matched_keyword = pattern.pattern
                        break

            if matched_keyword is not None:
                filtered_domains.append(domain)
                pattern_hits[matched_keyword] += 1
                log_domain_result(domain, "filtered", keyword=matched_keyword)
            else:
                clean_domains.append(domain)
                log_domain_result(domain, "clean")
            
            # Update progress bar
            pbar.update(1)
            
            # Update description with current stats
            if idx % 1000 == 0 or idx == total_domains:
                pbar.set_description(
                    f"{Fore.CYAN}Filtering domains{Style.RESET_ALL} "
                    f"{Fore.GREEN}(Clean: {len(clean_domains):,}){Style.RESET_ALL} "
                    f"{Fore.RED}(Filtered: {len(filtered_domains):,}){Style.RESET_ALL}"
                )
    
    # Write results to files
    print_status("💾 Writing results to files...", "progress")
    
    # Write clean domains to main output file
    with open(main_output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(clean_domains))
    
    # Write filtered domains
    with open(filtered_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(filtered_domains))
    
    # Calculate statistics
    elapsed_time = time.time() - start_time
    clean_count = len(clean_domains)
    filtered_count = len(filtered_domains)
    filter_rate = (filtered_count / total_domains) * 100 if total_domains > 0 else 0
    
    clean_rate = (clean_count / total_domains) * 100 if total_domains else 0
    
    # Print final results in detailed summary format
    summary_lines = [
        "\n" + "=" * 60,
        "FILTERING RESULTS",
        "=" * 60,
        f"Processing time: {elapsed_time:.2f} seconds",
        f"Total domains processed: {total_domains:,}",
        f"Clean domains: {clean_count:,} ({clean_rate:.1f}%)",
        f"Filtered domains: {filtered_count:,} ({filter_rate:.1f}%)",
        "Files created:",
        f"   - Main file: {main_output_file}",
        f"   - Filtered domains: {filtered_file}",
        "=" * 60,
        ""
    ]
    
    for line in summary_lines:
        print(line)
        logger.info(line)
    
    # Show some sample filtered domains
    if filtered_domains:
        print("Sample filtered domains (first 10):")
        logger.info("Sample filtered domains (first 10):")
        for i, domain in enumerate(filtered_domains[:10], 1):
            entry = f"   {i:2d}. {domain}"
            print(entry)
            logger.info(entry)
        remaining = len(filtered_domains) - 10
        if remaining > 0:
            tail = f"   ... and {remaining:,} more"
            print(tail)
            logger.info(tail)
        print()
    
    # Display top keyword hits
    if pattern_hits:
        print("Top 20 filter hits:")
        logger.info("Top 20 filter hits:")
        for pattern, hits in pattern_hits.most_common(20):
            entry = f"   - {pattern} - {hits:,} domains filtered"
            print(entry)
            logger.info(entry)
        print()
    run_qc_check(script_dir, clean_domains, filtered_domains)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\n⚠️  Process interrupted by user", "warning")
    except Exception as e:
        print_status(f"\n❌ Unexpected error: {e}", "error")
        raise







